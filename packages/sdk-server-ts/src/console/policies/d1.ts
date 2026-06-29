import { secureRandomBase36 } from '@shared/utils/secureRandomId';
import {
  d1Integer as toNumber,
  d1ChangedRows,
  formatD1ExecStatement,
  parseD1JsonObjectColumn,
  queryD1All,
  queryD1One,
  type D1Row,
} from '../../storage/d1Sql';
import type { D1DatabaseLike } from '../../storage/tenantRoute';
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
  ConsolePolicy,
  ConsolePolicyAssignment,
  ConsolePolicyAssignmentScopeType,
  ConsolePolicyKind,
  ConsolePolicyStatus,
  ConsolePolicyVersion,
  ConsolePolicyWalletScopeRef,
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

const DEFAULT_POLICY_NAME = 'Default Policy';
const DEFAULT_POLICY_DESCRIPTION = 'Default policy profile for this organization';

export const CONSOLE_POLICY_D1_RUNTIME = Symbol('consolePolicyD1Runtime');

export interface ConsolePolicyD1Runtime {
  database: D1DatabaseLike;
  namespace: string;
  now: () => Date;
}

export type ConsolePolicyD1Service = ConsolePolicyService & {
  [CONSOLE_POLICY_D1_RUNTIME]: ConsolePolicyD1Runtime;
};

export interface D1ConsolePolicySchemaOptions {
  database: D1DatabaseLike;
}

export interface D1ConsolePolicyServiceOptions {
  database: D1DatabaseLike;
  namespace?: string;
  ensureSchema?: boolean;
  now?: () => Date;
}

interface D1ConsolePolicyState {
  database: D1DatabaseLike;
  namespace: string;
  now: () => Date;
}

export const CONSOLE_POLICY_D1_SCHEMA_SQL = Object.freeze([
  `
    CREATE TABLE IF NOT EXISTS policies (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      id TEXT NOT NULL,
      kind TEXT NOT NULL DEFAULT 'TRANSACTION',
      name TEXT NOT NULL,
      description TEXT,
      status TEXT NOT NULL,
      version INTEGER NOT NULL,
      rules_json TEXT NOT NULL,
      created_at_ms INTEGER NOT NULL,
      updated_at_ms INTEGER NOT NULL,
      published_at_ms INTEGER,
      is_system_default INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (namespace, org_id, id),
      CHECK (kind IN ('TRANSACTION', 'GAS_SPONSORSHIP')),
      CHECK (status IN ('DRAFT', 'PUBLISHED', 'ARCHIVED')),
      CHECK (version >= 0),
      CHECK (is_system_default IN (0, 1)),
      CHECK (json_valid(rules_json))
    )
  `,
  `
    CREATE UNIQUE INDEX IF NOT EXISTS policies_namespace_id_uidx
      ON policies (namespace, id)
  `,
  `
    CREATE UNIQUE INDEX IF NOT EXISTS policies_org_system_default_uidx
      ON policies (namespace, org_id)
      WHERE is_system_default = 1
  `,
  `
    CREATE INDEX IF NOT EXISTS policies_org_updated_idx
      ON policies (namespace, org_id, updated_at_ms DESC, created_at_ms DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS policies_org_status_idx
      ON policies (namespace, org_id, status)
  `,
  `
    CREATE TABLE IF NOT EXISTS policy_versions (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      policy_id TEXT NOT NULL,
      kind TEXT NOT NULL DEFAULT 'TRANSACTION',
      version INTEGER NOT NULL,
      status TEXT NOT NULL,
      rules_json TEXT NOT NULL,
      published_at_ms INTEGER,
      created_at_ms INTEGER NOT NULL,
      actor_user_id TEXT NOT NULL,
      PRIMARY KEY (namespace, org_id, policy_id, version),
      FOREIGN KEY (namespace, org_id, policy_id)
        REFERENCES policies(namespace, org_id, id)
        ON DELETE CASCADE,
      CHECK (kind IN ('TRANSACTION', 'GAS_SPONSORSHIP')),
      CHECK (status IN ('DRAFT', 'PUBLISHED', 'ARCHIVED')),
      CHECK (version >= 0),
      CHECK (json_valid(rules_json))
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS policy_versions_org_policy_created_idx
      ON policy_versions (namespace, org_id, policy_id, created_at_ms DESC)
  `,
  `
    CREATE TABLE IF NOT EXISTS policy_assignments (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      id TEXT NOT NULL,
      scope_type TEXT NOT NULL,
      scope_id TEXT NOT NULL,
      policy_id TEXT NOT NULL,
      created_at_ms INTEGER NOT NULL,
      updated_at_ms INTEGER NOT NULL,
      PRIMARY KEY (namespace, org_id, id),
      UNIQUE (namespace, org_id, scope_type, scope_id),
      FOREIGN KEY (namespace, org_id, policy_id)
        REFERENCES policies(namespace, org_id, id)
        ON DELETE CASCADE,
      CHECK (scope_type IN ('ORG', 'PROJECT', 'ENVIRONMENT', 'WALLET'))
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS policy_assignments_org_updated_idx
      ON policy_assignments (namespace, org_id, updated_at_ms DESC, created_at_ms DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS policy_assignments_org_scope_idx
      ON policy_assignments (namespace, org_id, scope_type, scope_id)
  `,
] as const);

export async function ensureConsolePolicyD1Schema(
  options: D1ConsolePolicySchemaOptions,
): Promise<void> {
  for (const statement of CONSOLE_POLICY_D1_SCHEMA_SQL) {
    await options.database.exec(formatD1ExecStatement(statement));
  }
}

export function getConsolePolicyD1Runtime(
  service: ConsolePolicyService | null | undefined,
): ConsolePolicyD1Runtime | null {
  if (!service || typeof service !== 'object') return null;
  return (service as Partial<ConsolePolicyD1Service>)[CONSOLE_POLICY_D1_RUNTIME] || null;
}

function defaultNow(): Date {
  return new Date();
}

function ensureNamespace(namespace: string | undefined): string {
  const normalized = String(namespace || 'default').trim();
  return normalized || 'default';
}

function nowMs(now: Date): number {
  return now.getTime();
}

function toIso(ms: number): string {
  return new Date(ms).toISOString();
}

function nullableIso(value: unknown): string | null {
  if (value === null || value === undefined || value === '') return null;
  const parsed = toNumber(value);
  return parsed > 0 ? toIso(parsed) : null;
}


function normalizeOptionalString(value: unknown): string | null {
  const normalized = String(value || '').trim();
  return normalized || null;
}

function makeId(prefix: string, now: Date): string {
  return `${prefix}_${now.getTime().toString(36)}_${secureRandomBase36(8, 'console IDs')}`;
}


function isD1ConstraintError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error || '');
  return message.includes('UNIQUE constraint failed') || message.includes('constraint failed');
}

function parseBooleanFlag(value: unknown): boolean {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'number') return value === 1;
  const normalized = String(value || '')
    .trim()
    .toLowerCase();
  return normalized === '1' || normalized === 'true' || normalized === 't';
}

function parsePolicyKind(value: unknown): ConsolePolicyKind {
  const normalized = String(value || '')
    .trim()
    .toUpperCase();
  switch (normalized) {
    case 'GAS_SPONSORSHIP':
      return 'GAS_SPONSORSHIP';
    case 'TRANSACTION':
    case '':
      return 'TRANSACTION';
    default:
      throw new Error(`Invalid console policy kind row: ${normalized}`);
  }
}

function parsePolicyStatus(value: unknown): ConsolePolicyStatus {
  const normalized = String(value || '')
    .trim()
    .toUpperCase();
  switch (normalized) {
    case 'DRAFT':
    case 'PUBLISHED':
    case 'ARCHIVED':
      return normalized;
    default:
      throw new Error(`Invalid console policy status row: ${normalized || 'empty'}`);
  }
}

function parseAssignmentScopeType(value: unknown): ConsolePolicyAssignmentScopeType {
  const normalized = normalizeScopeType(String(value || 'ORG'));
  switch (normalized) {
    case 'ORG':
    case 'PROJECT':
    case 'ENVIRONMENT':
    case 'WALLET':
      return normalized;
    default:
      throw new Error(`Invalid console policy assignment scope row: ${normalized || 'empty'}`);
  }
}

function parseRulesJson(value: unknown): Record<string, unknown> {
  return parseD1JsonObjectColumn(value);
}

function rulesJson(rules: ConsolePolicy['rules']): string {
  return JSON.stringify(serializeConsolePolicyRules(rules));
}

function parsePolicyRow(row: D1Row): ConsolePolicy {
  const kind = parsePolicyKind(row.kind);
  return {
    id: String(row.id || '').trim(),
    orgId: String(row.org_id || '').trim(),
    isSystemDefault: parseBooleanFlag(row.is_system_default),
    kind,
    name: String(row.name || ''),
    description: normalizeOptionalString(row.description),
    status: parsePolicyStatus(row.status || 'DRAFT'),
    version: toNumber(row.version),
    rules: parseStoredConsolePolicyRules(parseRulesJson(row.rules_json), kind),
    createdAt: toIso(toNumber(row.created_at_ms)),
    updatedAt: toIso(toNumber(row.updated_at_ms)),
    publishedAt: nullableIso(row.published_at_ms),
  };
}

function parsePolicyVersionRow(row: D1Row): ConsolePolicyVersion {
  const kind = parsePolicyKind(row.kind);
  return {
    policyId: String(row.policy_id || '').trim(),
    kind,
    version: toNumber(row.version),
    status: parsePolicyStatus(row.status || 'PUBLISHED'),
    rules: parseStoredConsolePolicyRules(parseRulesJson(row.rules_json), kind),
    publishedAt: nullableIso(row.published_at_ms),
    createdAt: toIso(toNumber(row.created_at_ms)),
    actorUserId: String(row.actor_user_id || '').trim(),
  };
}

function parseAssignmentRow(row: D1Row): ConsolePolicyAssignment {
  return {
    id: String(row.id || '').trim(),
    orgId: String(row.org_id || '').trim(),
    scopeType: parseAssignmentScopeType(row.scope_type),
    scopeId: String(row.scope_id || '').trim(),
    policyId: String(row.policy_id || '').trim(),
    createdAt: toIso(toNumber(row.created_at_ms)),
    updatedAt: toIso(toNumber(row.updated_at_ms)),
  };
}

async function policyIdExists(state: D1ConsolePolicyState, policyId: string): Promise<boolean> {
  const row = await queryD1One(
    state.database,
    `SELECT id
       FROM policies
      WHERE namespace = ?
        AND id = ?
      LIMIT 1`,
    [state.namespace, policyId],
  );
  return Boolean(row);
}

async function generatePolicyId(
  state: D1ConsolePolicyState,
  now: Date,
): Promise<string> {
  for (let attempt = 0; attempt < 8; attempt += 1) {
    const candidate = makeId('policy', now);
    if (!(await policyIdExists(state, candidate))) return candidate;
  }
  throw new ConsolePolicyError('internal', 500, 'Failed to generate a unique policy id');
}

async function findPolicy(input: {
  state: D1ConsolePolicyState;
  orgId: string;
  policyId: string;
}): Promise<ConsolePolicy | null> {
  const row = await queryD1One(
    input.state.database,
    `SELECT *
       FROM policies
      WHERE namespace = ?
        AND org_id = ?
        AND id = ?
      LIMIT 1`,
    [input.state.namespace, input.orgId, input.policyId],
  );
  return row ? parsePolicyRow(row) : null;
}

async function findSystemDefaultPolicy(input: {
  state: D1ConsolePolicyState;
  orgId: string;
}): Promise<ConsolePolicy | null> {
  const row = await queryD1One(
    input.state.database,
    `SELECT *
       FROM policies
      WHERE namespace = ?
        AND org_id = ?
        AND is_system_default = 1
      ORDER BY created_at_ms ASC
      LIMIT 1`,
    [input.state.namespace, input.orgId],
  );
  return row ? parsePolicyRow(row) : null;
}

async function findAssignmentById(input: {
  state: D1ConsolePolicyState;
  orgId: string;
  assignmentId: string;
}): Promise<ConsolePolicyAssignment | null> {
  const row = await queryD1One(
    input.state.database,
    `SELECT *
       FROM policy_assignments
      WHERE namespace = ?
        AND org_id = ?
        AND id = ?
      LIMIT 1`,
    [input.state.namespace, input.orgId, input.assignmentId],
  );
  return row ? parseAssignmentRow(row) : null;
}

async function findAssignmentByScope(input: {
  state: D1ConsolePolicyState;
  orgId: string;
  scopeType: ConsolePolicyAssignmentScopeType;
  scopeId: string;
}): Promise<ConsolePolicyAssignment | null> {
  const row = await queryD1One(
    input.state.database,
    `SELECT *
       FROM policy_assignments
      WHERE namespace = ?
        AND org_id = ?
        AND scope_type = ?
        AND scope_id = ?
      LIMIT 1`,
    [input.state.namespace, input.orgId, input.scopeType, input.scopeId],
  );
  return row ? parseAssignmentRow(row) : null;
}

function defaultPolicyInsertStatement(input: {
  state: D1ConsolePolicyState;
  ctx: ConsolePoliciesContext;
  policyId: string;
  rules: ConsolePolicy['rules'];
  createdAtMs: number;
}) {
  return input.state.database
    .prepare(
      `INSERT INTO policies
        (namespace, org_id, id, kind, name, description, status, version, rules_json, created_at_ms, updated_at_ms, published_at_ms, is_system_default)
       VALUES
        (?, ?, ?, 'TRANSACTION', ?, ?, 'PUBLISHED', 1, ?, ?, ?, ?, 1)`,
    )
    .bind(
      input.state.namespace,
      input.ctx.orgId,
      input.policyId,
      DEFAULT_POLICY_NAME,
      DEFAULT_POLICY_DESCRIPTION,
      rulesJson(input.rules),
      input.createdAtMs,
      input.createdAtMs,
      input.createdAtMs,
    );
}

function defaultPolicyVersionInsertStatement(input: {
  state: D1ConsolePolicyState;
  ctx: ConsolePoliciesContext;
  policyId: string;
  rules: ConsolePolicy['rules'];
  createdAtMs: number;
}) {
  return input.state.database
    .prepare(
      `INSERT INTO policy_versions
        (namespace, org_id, policy_id, kind, version, status, rules_json, published_at_ms, created_at_ms, actor_user_id)
       VALUES
        (?, ?, ?, 'TRANSACTION', 1, 'PUBLISHED', ?, ?, ?, 'system-bootstrap')
       ON CONFLICT(namespace, org_id, policy_id, version) DO NOTHING`,
    )
    .bind(
      input.state.namespace,
      input.ctx.orgId,
      input.policyId,
      rulesJson(input.rules),
      input.createdAtMs,
      input.createdAtMs,
    );
}

function defaultPolicyAssignmentInsertStatement(input: {
  state: D1ConsolePolicyState;
  ctx: ConsolePoliciesContext;
  assignmentId: string;
  policyId: string;
  createdAtMs: number;
}) {
  return input.state.database
    .prepare(
      `INSERT INTO policy_assignments
        (namespace, org_id, id, scope_type, scope_id, policy_id, created_at_ms, updated_at_ms)
       VALUES
        (?, ?, ?, 'ORG', ?, ?, ?, ?)
       ON CONFLICT(namespace, org_id, scope_type, scope_id) DO NOTHING`,
    )
    .bind(
      input.state.namespace,
      input.ctx.orgId,
      input.assignmentId,
      input.ctx.orgId,
      input.policyId,
      input.createdAtMs,
      input.createdAtMs,
    );
}

async function ensureDefaultPolicy(
  state: D1ConsolePolicyState,
  ctx: ConsolePoliciesContext,
): Promise<void> {
  const existingDefault = await findSystemDefaultPolicy({ state, orgId: ctx.orgId });
  if (existingDefault) return;

  const createdAt = state.now();
  const createdAtMs = nowMs(createdAt);
  const rules = createDefaultConsolePolicyRules('TRANSACTION');
  for (let attempt = 0; attempt < 8; attempt += 1) {
    const policyId = await generatePolicyId(state, createdAt);
    try {
      await state.database.batch([
        defaultPolicyInsertStatement({ state, ctx, policyId, rules, createdAtMs }),
        defaultPolicyVersionInsertStatement({ state, ctx, policyId, rules, createdAtMs }),
        defaultPolicyAssignmentInsertStatement({
          state,
          ctx,
          assignmentId: makeId('policy_assignment', createdAt),
          policyId,
          createdAtMs,
        }),
      ]);
      return;
    } catch (error: unknown) {
      if (!isD1ConstraintError(error)) throw error;
      const concurrentDefault = await findSystemDefaultPolicy({ state, orgId: ctx.orgId });
      if (concurrentDefault) return;
    }
  }
  throw new ConsolePolicyError('internal', 500, 'Failed to create default policy');
}

function createPolicyInsertStatement(input: {
  state: D1ConsolePolicyState;
  ctx: ConsolePoliciesContext;
  policyId: string;
  request: CreateConsolePolicyRequest;
  rules: ConsolePolicy['rules'];
  createdAtMs: number;
}) {
  return input.state.database
    .prepare(
      `INSERT INTO policies
        (namespace, org_id, id, kind, name, description, status, version, rules_json, created_at_ms, updated_at_ms, published_at_ms, is_system_default)
       VALUES
        (?, ?, ?, ?, ?, ?, 'DRAFT', 0, ?, ?, ?, NULL, 0)`,
    )
    .bind(
      input.state.namespace,
      input.ctx.orgId,
      input.policyId,
      input.request.kind || 'TRANSACTION',
      input.request.name,
      input.request.description || null,
      rulesJson(input.rules),
      input.createdAtMs,
      input.createdAtMs,
    );
}

function upsertAssignmentStatement(input: {
  state: D1ConsolePolicyState;
  ctx: ConsolePoliciesContext;
  request: UpsertConsolePolicyAssignmentRequest;
  assignmentId: string;
  updatedAtMs: number;
}) {
  const scopeType = parseAssignmentScopeType(input.request.scopeType);
  const scopeId = String(input.request.scopeId || '').trim();
  return input.state.database
    .prepare(
      `INSERT INTO policy_assignments
        (namespace, org_id, id, scope_type, scope_id, policy_id, created_at_ms, updated_at_ms)
       VALUES
        (?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(namespace, org_id, scope_type, scope_id)
       DO UPDATE
         SET policy_id = excluded.policy_id,
             updated_at_ms = excluded.updated_at_ms`,
    )
    .bind(
      input.state.namespace,
      input.ctx.orgId,
      input.assignmentId,
      scopeType,
      scopeId,
      input.request.policyId,
      input.updatedAtMs,
      input.updatedAtMs,
    );
}

async function upsertAssignmentRow(input: {
  state: D1ConsolePolicyState;
  ctx: ConsolePoliciesContext;
  request: UpsertConsolePolicyAssignmentRequest;
  now: Date;
}): Promise<ConsolePolicyAssignment> {
  const scopeType = parseAssignmentScopeType(input.request.scopeType);
  const scopeId = String(input.request.scopeId || '').trim();
  await upsertAssignmentStatement({
    state: input.state,
    ctx: input.ctx,
    request: input.request,
    assignmentId: makeId('policy_assignment', input.now),
    updatedAtMs: nowMs(input.now),
  }).run();
  const assignment = await findAssignmentByScope({
    state: input.state,
    orgId: input.ctx.orgId,
    scopeType,
    scopeId,
  });
  if (!assignment) {
    throw new ConsolePolicyError('internal', 500, 'Failed to upsert policy assignment');
  }
  return assignment;
}

async function createPolicyInD1(input: {
  state: D1ConsolePolicyState;
  ctx: ConsolePoliciesContext;
  request: CreateConsolePolicyRequest;
}): Promise<ConsolePolicy> {
  await ensureDefaultPolicy(input.state, input.ctx);
  const createdAt = input.state.now();
  const createdAtMs = nowMs(createdAt);
  const kind = input.request.kind || 'TRANSACTION';
  const rules = parseConsolePolicyRulesInput(input.request.rules, kind);
  for (let attempt = 0; attempt < 8; attempt += 1) {
    const policyId = await generatePolicyId(input.state, createdAt);
    try {
      const statements = [
        createPolicyInsertStatement({
          state: input.state,
          ctx: input.ctx,
          policyId,
          request: input.request,
          rules,
          createdAtMs,
        }),
      ];
      if (input.request.assignment) {
        statements.push(
          upsertAssignmentStatement({
            state: input.state,
            ctx: input.ctx,
            request: {
              scopeType: input.request.assignment.scopeType,
              scopeId: input.request.assignment.scopeId,
              policyId,
            },
            assignmentId: makeId('policy_assignment', createdAt),
            updatedAtMs: createdAtMs,
          }),
        );
      }
      await input.state.database.batch(statements);
      const policy = await findPolicy({
        state: input.state,
        orgId: input.ctx.orgId,
        policyId,
      });
      if (!policy) {
        throw new ConsolePolicyError('internal', 500, 'Failed to create policy');
      }
      return policy;
    } catch (error: unknown) {
      if (isD1ConstraintError(error)) continue;
      throw error;
    }
  }
  throw new ConsolePolicyError('internal', 500, 'Failed to generate a unique policy id');
}

async function publishPolicyInD1(input: {
  state: D1ConsolePolicyState;
  ctx: ConsolePoliciesContext;
  policy: ConsolePolicy;
}): Promise<PublishConsolePolicyResult | null> {
  const publishedAtMs = nowMs(input.state.now());
  await input.state.database.batch([
    input.state.database
      .prepare(
        `UPDATE policies
            SET status = 'PUBLISHED',
                version = version + 1,
                updated_at_ms = ?,
                published_at_ms = ?
          WHERE namespace = ?
            AND org_id = ?
            AND id = ?`,
      )
      .bind(
        publishedAtMs,
        publishedAtMs,
        input.state.namespace,
        input.ctx.orgId,
        input.policy.id,
      ),
    input.state.database
      .prepare(
        `INSERT INTO policy_versions
          (namespace, org_id, policy_id, kind, version, status, rules_json, published_at_ms, created_at_ms, actor_user_id)
         SELECT namespace,
                org_id,
                id,
                kind,
                version,
                status,
                rules_json,
                published_at_ms,
                ?,
                ?
           FROM policies
          WHERE namespace = ?
            AND org_id = ?
            AND id = ?
         ON CONFLICT(namespace, org_id, policy_id, version) DO NOTHING`,
      )
      .bind(
        publishedAtMs,
        input.ctx.actorUserId,
        input.state.namespace,
        input.ctx.orgId,
        input.policy.id,
      ),
  ]);
  const policy = await findPolicy({
    state: input.state,
    orgId: input.ctx.orgId,
    policyId: input.policy.id,
  });
  if (!policy) return null;
  return { published: true, policy };
}

function appendListFilter(input: {
  clauses: string[];
  values: unknown[];
  clause: string;
  value: unknown;
}): void {
  input.clauses.push(input.clause);
  input.values.push(input.value);
}

export async function createD1ConsolePolicyService(
  options: D1ConsolePolicyServiceOptions,
): Promise<ConsolePolicyService> {
  if (options.ensureSchema) {
    await ensureConsolePolicyD1Schema({ database: options.database });
  }
  const state: D1ConsolePolicyState = {
    database: options.database,
    namespace: ensureNamespace(options.namespace),
    now: options.now || defaultNow,
  };
  const runtime: ConsolePolicyD1Runtime = {
    database: state.database,
    namespace: state.namespace,
    now: state.now,
  };

  const service: ConsolePolicyD1Service = {
    async listPolicies(
      ctx: ConsolePoliciesContext,
      request: ListConsolePoliciesRequest = {},
    ): Promise<ConsolePolicy[]> {
      await ensureDefaultPolicy(state, ctx);
      const clauses = ['namespace = ?', 'org_id = ?'];
      const values: unknown[] = [state.namespace, ctx.orgId];
      if (request.kind) {
        appendListFilter({
          clauses,
          values,
          clause: 'kind = ?',
          value: parsePolicyKind(request.kind),
        });
      }
      const rows = await queryD1All(
        state.database,
        `SELECT *
           FROM policies
          WHERE ${clauses.join(' AND ')}
          ORDER BY updated_at_ms DESC, created_at_ms DESC`,
        values,
      );
      return rows.map(parsePolicyRow);
    },

    async getPolicy(ctx: ConsolePoliciesContext, policyId: string): Promise<ConsolePolicy | null> {
      await ensureDefaultPolicy(state, ctx);
      return await findPolicy({ state, orgId: ctx.orgId, policyId });
    },

    async listPolicyVersions(
      ctx: ConsolePoliciesContext,
      policyId: string,
    ): Promise<ConsolePolicyVersion[] | null> {
      await ensureDefaultPolicy(state, ctx);
      const current = await findPolicy({ state, orgId: ctx.orgId, policyId });
      if (!current) return null;
      const rows = await queryD1All(
        state.database,
        `SELECT *
           FROM policy_versions
          WHERE namespace = ?
            AND org_id = ?
            AND policy_id = ?
          ORDER BY version DESC, created_at_ms DESC`,
        [state.namespace, ctx.orgId, policyId],
      );
      return rows.map(parsePolicyVersionRow);
    },

    async createPolicy(
      ctx: ConsolePoliciesContext,
      request: CreateConsolePolicyRequest,
    ): Promise<ConsolePolicy> {
      return await createPolicyInD1({ state, ctx, request });
    },

    async updatePolicy(
      ctx: ConsolePoliciesContext,
      policyId: string,
      request: UpdateConsolePolicyRequest,
    ): Promise<ConsolePolicy | null> {
      await ensureDefaultPolicy(state, ctx);
      const current = await findPolicy({ state, orgId: ctx.orgId, policyId });
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
      const updatedAtMs = nowMs(state.now());
      await state.database
        .prepare(
          `UPDATE policies
              SET name = ?,
                  description = ?,
                  rules_json = ?,
                  status = 'DRAFT',
                  updated_at_ms = ?
            WHERE namespace = ?
              AND org_id = ?
              AND id = ?`,
        )
        .bind(
          request.name || current.name,
          request.description !== undefined ? request.description || null : current.description,
          rulesJson(rules),
          updatedAtMs,
          state.namespace,
          ctx.orgId,
          policyId,
        )
        .run();
      return await findPolicy({ state, orgId: ctx.orgId, policyId });
    },

    async publishPolicy(
      ctx: ConsolePoliciesContext,
      policyId: string,
    ): Promise<PublishConsolePolicyResult | null> {
      await ensureDefaultPolicy(state, ctx);
      const current = await findPolicy({ state, orgId: ctx.orgId, policyId });
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
      return await publishPolicyInD1({ state, ctx, policy: current });
    },

    async deletePolicy(
      ctx: ConsolePoliciesContext,
      policyId: string,
    ): Promise<DeleteConsolePolicyResult> {
      await ensureDefaultPolicy(state, ctx);
      const current = await findPolicy({ state, orgId: ctx.orgId, policyId });
      if (!current) return { removed: false, policy: null };
      if (current.isSystemDefault) {
        throw new ConsolePolicyError(
          'default_policy_protected',
          409,
          `Policy ${policyId} is the organization default and cannot be deleted`,
        );
      }
      await state.database.batch([
        state.database
          .prepare(
            `DELETE FROM policy_assignments
              WHERE namespace = ?
                AND org_id = ?
                AND policy_id = ?`,
          )
          .bind(state.namespace, ctx.orgId, policyId),
        state.database
          .prepare(
            `DELETE FROM policy_versions
              WHERE namespace = ?
                AND org_id = ?
                AND policy_id = ?`,
          )
          .bind(state.namespace, ctx.orgId, policyId),
        state.database
          .prepare(
            `DELETE FROM policies
              WHERE namespace = ?
                AND org_id = ?
                AND id = ?`,
          )
          .bind(state.namespace, ctx.orgId, policyId),
      ]);
      return { removed: true, policy: current };
    },

    async simulatePolicy(
      ctx: ConsolePoliciesContext,
      policyId: string,
      request: SimulateConsolePolicyRequest,
    ): Promise<SimulateConsolePolicyResult | null> {
      await ensureDefaultPolicy(state, ctx);
      const policy = await findPolicy({ state, orgId: ctx.orgId, policyId });
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
        evaluatedAt: state.now().toISOString(),
        policyVersion: policy.version,
        normalizedRequest: evaluation.normalizedRequest,
      };
    },

    async listAssignments(
      ctx: ConsolePoliciesContext,
      request: ListConsolePolicyAssignmentsRequest = {},
    ): Promise<ConsolePolicyAssignment[]> {
      await ensureDefaultPolicy(state, ctx);
      const clauses = ['namespace = ?', 'org_id = ?'];
      const values: unknown[] = [state.namespace, ctx.orgId];
      if (request.scopeType) {
        appendListFilter({
          clauses,
          values,
          clause: 'scope_type = ?',
          value: parseAssignmentScopeType(request.scopeType),
        });
      }
      const scopeId = String(request.scopeId || '').trim();
      if (scopeId) {
        appendListFilter({ clauses, values, clause: 'scope_id = ?', value: scopeId });
      }
      const rows = await queryD1All(
        state.database,
        `SELECT *
           FROM policy_assignments
          WHERE ${clauses.join(' AND ')}
          ORDER BY updated_at_ms DESC, created_at_ms DESC`,
        values,
      );
      return rows.map(parseAssignmentRow);
    },

    async upsertAssignment(
      ctx: ConsolePoliciesContext,
      request: UpsertConsolePolicyAssignmentRequest,
    ): Promise<ConsolePolicyAssignment> {
      await ensureDefaultPolicy(state, ctx);
      const policy = await findPolicy({ state, orgId: ctx.orgId, policyId: request.policyId });
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
      return await upsertAssignmentRow({ state, ctx, request, now: state.now() });
    },

    async deleteAssignment(
      ctx: ConsolePoliciesContext,
      assignmentId: string,
    ): Promise<{ removed: boolean; assignment: ConsolePolicyAssignment | null }> {
      await ensureDefaultPolicy(state, ctx);
      const current = await findAssignmentById({ state, orgId: ctx.orgId, assignmentId });
      if (!current) return { removed: false, assignment: null };
      const result = await state.database
        .prepare(
          `DELETE FROM policy_assignments
            WHERE namespace = ?
              AND org_id = ?
              AND id = ?`,
        )
        .bind(state.namespace, ctx.orgId, assignmentId)
        .run();
      return { removed: d1ChangedRows(result) > 0, assignment: current };
    },

    async resolvePoliciesForWallets(
      ctx: ConsolePoliciesContext,
      wallets: ConsolePolicyWalletScopeRef[],
    ): Promise<Record<string, string | null>> {
      await ensureDefaultPolicy(state, ctx);
      const rows = await queryD1All(
        state.database,
        `SELECT a.scope_type, a.scope_id, a.policy_id
           FROM policy_assignments a
           JOIN policies p
             ON p.namespace = a.namespace
            AND p.org_id = a.org_id
            AND p.id = a.policy_id
          WHERE a.namespace = ?
            AND a.org_id = ?
            AND p.published_at_ms IS NOT NULL
            AND p.version > 0`,
        [state.namespace, ctx.orgId],
      );
      const byScope = new Map<string, string>();
      for (const row of rows) {
        const scopeType = parseAssignmentScopeType(row.scope_type);
        const scopeId = String(row.scope_id || '').trim();
        const resolvedPolicyId = String(row.policy_id || '').trim();
        if (!scopeId || !resolvedPolicyId) continue;
        byScope.set(assignmentScopeKey(scopeType, scopeId), resolvedPolicyId);
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

    [CONSOLE_POLICY_D1_RUNTIME]: runtime,
  };
  return service;
}
