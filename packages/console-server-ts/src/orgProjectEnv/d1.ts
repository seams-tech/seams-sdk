import { secureRandomBase36 } from '@seams-internal/shared-ts/utils/secureRandomId';
import { d1Number as toNumber, d1ChangedRows, formatD1ExecStatement, queryD1All, queryD1One, type D1Row } from '@seams/sdk-server/internal/storage/d1Sql';
import type {
  D1DatabaseLike,
  D1PreparedStatementLike,
} from '@seams/sdk-server/internal/storage/tenantRoute';
import { ConsoleOrgProjectEnvError } from './errors';
import { DEFAULT_CONSOLE_SIGNING_ROOT_VERSION } from './types';
import type {
  ConsoleEnvironment,
  ConsoleEnvironmentStatus,
  ConsoleOrganization,
  ConsoleOrganizationStatus,
  ConsoleProject,
  ConsoleProjectStatus,
  CreateConsoleEnvironmentRequest,
  CreateConsoleProjectRequest,
  ListConsoleEnvironmentsRequest,
  ListConsoleProjectsRequest,
  SearchConsoleOrganizationsRequest,
  UpsertConsoleOrganizationRequest,
  UpdateConsoleEnvironmentRequest,
  UpdateConsoleProjectRequest,
} from './types';
import type { ConsoleOrgProjectEnvContext, ConsoleOrgProjectEnvService } from './service';

type ConsoleEnvironmentKey = ConsoleEnvironment['key'];

const DEFAULT_ENVIRONMENT_KEYS: readonly ConsoleEnvironmentKey[] = ['dev', 'staging', 'prod'];

export const CONSOLE_ORG_PROJECT_ENV_D1_RUNTIME = Symbol('consoleOrgProjectEnvD1Runtime');

export interface ConsoleOrgProjectEnvD1Runtime {
  database: D1DatabaseLike;
  namespace: string;
  now: () => Date;
}

export type ConsoleOrgProjectEnvD1Service = ConsoleOrgProjectEnvService & {
  [CONSOLE_ORG_PROJECT_ENV_D1_RUNTIME]: ConsoleOrgProjectEnvD1Runtime;
};

export interface D1ConsoleOrgProjectEnvServiceOptions {
  database: D1DatabaseLike;
  namespace?: string;
  ensureSchema?: boolean;
  now?: () => Date;
}

export interface D1ConsoleOrgProjectEnvSchemaOptions {
  database: D1DatabaseLike;
}

export const CONSOLE_ORG_PROJECT_ENV_D1_SCHEMA_SQL = Object.freeze([
  `
    CREATE TABLE IF NOT EXISTS organizations (
      namespace TEXT NOT NULL,
      id TEXT NOT NULL,
      name TEXT NOT NULL,
      slug TEXT NOT NULL,
      created_by_user_id TEXT,
      status TEXT NOT NULL,
      created_at_ms INTEGER NOT NULL,
      updated_at_ms INTEGER NOT NULL,
      PRIMARY KEY (namespace, id),
      CHECK (status IN ('ACTIVE'))
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS projects (
      namespace TEXT NOT NULL,
      id TEXT NOT NULL,
      org_id TEXT NOT NULL,
      name TEXT NOT NULL,
      slug TEXT NOT NULL,
      status TEXT NOT NULL,
      created_at_ms INTEGER NOT NULL,
      updated_at_ms INTEGER NOT NULL,
      PRIMARY KEY (namespace, id),
      CHECK (status IN ('ACTIVE', 'ARCHIVED')),
      FOREIGN KEY (namespace, org_id)
        REFERENCES organizations(namespace, id)
        ON DELETE CASCADE
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS projects_org_updated_idx
      ON projects (namespace, org_id, updated_at_ms DESC, created_at_ms DESC)
  `,
  `
    CREATE UNIQUE INDEX IF NOT EXISTS projects_namespace_id_org_unique_idx
      ON projects (namespace, id, org_id)
  `,
  `
    CREATE TABLE IF NOT EXISTS environments (
      namespace TEXT NOT NULL,
      id TEXT NOT NULL,
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      env_key TEXT NOT NULL,
      signing_root_version TEXT NOT NULL DEFAULT 'default',
      name TEXT NOT NULL,
      status TEXT NOT NULL,
      created_at_ms INTEGER NOT NULL,
      updated_at_ms INTEGER NOT NULL,
      PRIMARY KEY (namespace, id),
      CHECK (status IN ('ACTIVE', 'DISABLED', 'ARCHIVED')),
      CHECK (env_key IN ('dev', 'staging', 'prod')),
      UNIQUE (namespace, project_id, env_key),
      FOREIGN KEY (namespace, project_id, org_id)
        REFERENCES projects(namespace, id, org_id)
        ON DELETE CASCADE
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS environments_org_project_updated_idx
      ON environments (namespace, org_id, project_id, updated_at_ms DESC, created_at_ms DESC)
  `,
  `
    CREATE UNIQUE INDEX IF NOT EXISTS environments_namespace_id_project_org_unique_idx
      ON environments (namespace, id, project_id, org_id)
  `,
] as const);

export async function ensureConsoleOrgProjectEnvD1Schema(
  options: D1ConsoleOrgProjectEnvSchemaOptions,
): Promise<void> {
  for (const statement of CONSOLE_ORG_PROJECT_ENV_D1_SCHEMA_SQL) {
    await options.database.exec(formatD1ExecStatement(statement));
  }
}

export function getConsoleOrgProjectEnvD1Runtime(
  service: ConsoleOrgProjectEnvService | null | undefined,
): ConsoleOrgProjectEnvD1Runtime | null {
  if (!service || typeof service !== 'object') return null;
  return (
    (service as Partial<ConsoleOrgProjectEnvD1Service>)[
      CONSOLE_ORG_PROJECT_ENV_D1_RUNTIME
    ] || null
  );
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


function normalizeOptionalString(value: unknown): string | null {
  const normalized = String(value || '').trim();
  return normalized || null;
}

function slugify(value: string): string {
  return (
    String(value || '')
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '') || 'default'
  );
}

function humanizeId(value: string, fallback: string): string {
  const trimmed = String(value || '').trim();
  if (!trimmed) return fallback;
  return trimmed
    .replace(/[_:-]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function environmentNameFromKey(key: ConsoleEnvironmentKey): string {
  if (key === 'dev') return 'Development';
  if (key === 'staging') return 'Staging';
  return 'Production';
}

function defaultEnvironmentStatus(
  key: ConsoleEnvironmentKey,
  liveEnvironmentsEnabled: boolean,
): Exclude<ConsoleEnvironmentStatus, 'ARCHIVED'> {
  if (key === 'dev') return 'ACTIVE';
  return liveEnvironmentsEnabled ? 'ACTIVE' : 'DISABLED';
}

function defaultEnvironmentId(projectId: string, key: ConsoleEnvironmentKey): string {
  return `${projectId}:${key}`;
}

function normalizeSigningRootVersion(input: unknown, fallback?: string): string {
  const normalized = String(input || '').trim();
  if (normalized) return normalized;
  if (fallback) return fallback;
  throw new ConsoleOrgProjectEnvError(
    'invalid_signing_root_version',
    400,
    'signingRootVersion is required',
  );
}

function makeResourceId(prefix: string, now: Date): string {
  return `${prefix}_${now.getTime().toString(36)}_${secureRandomBase36(6, 'console IDs')}`;
}

function parseOrganizationStatus(value: unknown): ConsoleOrganizationStatus {
  const normalized = String(value || '').trim();
  switch (normalized) {
    case 'ACTIVE':
      return normalized;
    default:
      throw new Error(`Invalid console organization status row: ${normalized || 'empty'}`);
  }
}

function parseProjectStatus(value: unknown): ConsoleProjectStatus {
  const normalized = String(value || '').trim();
  switch (normalized) {
    case 'ACTIVE':
    case 'ARCHIVED':
      return normalized;
    default:
      throw new Error(`Invalid console project status row: ${normalized || 'empty'}`);
  }
}

function parseEnvironmentStatus(value: unknown): ConsoleEnvironmentStatus {
  const normalized = String(value || '').trim();
  switch (normalized) {
    case 'ACTIVE':
    case 'DISABLED':
    case 'ARCHIVED':
      return normalized;
    default:
      throw new Error(`Invalid console environment status row: ${normalized || 'empty'}`);
  }
}

function parseEnvironmentKey(value: unknown): ConsoleEnvironmentKey {
  const normalized = String(value || '').trim();
  switch (normalized) {
    case 'dev':
    case 'staging':
    case 'prod':
      return normalized;
    default:
      throw new Error(`Invalid console environment key row: ${normalized || 'empty'}`);
  }
}

function parseOrgRow(row: D1Row): ConsoleOrganization {
  return {
    id: String(row.id || ''),
    name: String(row.name || ''),
    slug: String(row.slug || ''),
    status: parseOrganizationStatus(row.status),
    createdAt: toIso(toNumber(row.created_at_ms)),
    updatedAt: toIso(toNumber(row.updated_at_ms)),
  };
}

function parseProjectRow(row: D1Row): ConsoleProject {
  return {
    id: String(row.id || ''),
    orgId: String(row.org_id || ''),
    name: String(row.name || ''),
    slug: String(row.slug || ''),
    status: parseProjectStatus(row.status),
    environmentCount: Math.max(0, toNumber(row.environment_count)),
    createdAt: toIso(toNumber(row.created_at_ms)),
    updatedAt: toIso(toNumber(row.updated_at_ms)),
  };
}

function parseEnvironmentRow(row: D1Row): ConsoleEnvironment {
  return {
    id: String(row.id || ''),
    orgId: String(row.org_id || ''),
    projectId: String(row.project_id || ''),
    key: parseEnvironmentKey(row.env_key),
    signingRootVersion: normalizeSigningRootVersion(
      row.signing_root_version,
      DEFAULT_CONSOLE_SIGNING_ROOT_VERSION,
    ),
    name: String(row.name || ''),
    status: parseEnvironmentStatus(row.status),
    createdAt: toIso(toNumber(row.created_at_ms)),
    updatedAt: toIso(toNumber(row.updated_at_ms)),
  };
}

function normalizeOrganizationSearchValue(value: string): string {
  return String(value || '')
    .trim()
    .toLowerCase();
}

function scoreOrganizationSearchCandidate(query: string, value: string, offset: number): number {
  const normalized = normalizeOrganizationSearchValue(value);
  if (!normalized) return Number.POSITIVE_INFINITY;
  if (normalized === query) return offset;
  if (normalized.startsWith(query)) {
    return offset + 10 + Math.max(0, normalized.length - query.length);
  }
  const tokens = normalized.split(/[\s_-]+/).filter(Boolean);
  const tokenIndex = tokens.findIndex((token) => token.startsWith(query));
  if (tokenIndex >= 0) return offset + 30 + tokenIndex;
  const containsIndex = normalized.indexOf(query);
  if (containsIndex >= 0) return offset + 60 + containsIndex;
  return Number.POSITIVE_INFINITY;
}

function scoreOrganizationSearchResult(query: string, organization: ConsoleOrganization): number {
  return Math.min(
    scoreOrganizationSearchCandidate(query, organization.name, 0),
    scoreOrganizationSearchCandidate(query, organization.id, 20),
  );
}

function sortOrganizationSearchResults(
  items: ConsoleOrganization[],
  query: string,
): ConsoleOrganization[] {
  return [...items].sort((left, right) => {
    const scoreDiff =
      scoreOrganizationSearchResult(query, left) - scoreOrganizationSearchResult(query, right);
    if (scoreDiff !== 0) return scoreDiff;
    const primaryDiff = left.name.localeCompare(right.name);
    if (primaryDiff !== 0) return primaryDiff;
    return left.id.localeCompare(right.id);
  });
}

function environmentRank(key: ConsoleEnvironmentKey): number {
  if (key === 'prod') return 0;
  if (key === 'staging') return 1;
  return 2;
}

function sortEnvironments(items: readonly ConsoleEnvironment[]): ConsoleEnvironment[] {
  return [...items].sort((left, right) => {
    const keyRankDiff = environmentRank(left.key) - environmentRank(right.key);
    if (keyRankDiff !== 0) return keyRankDiff;
    const updatedAtDiff = right.updatedAt.localeCompare(left.updatedAt);
    if (updatedAtDiff !== 0) return updatedAtDiff;
    return right.createdAt.localeCompare(left.createdAt);
  });
}


function isD1ConstraintError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error || '');
  return message.includes('UNIQUE constraint failed') || message.includes('constraint failed');
}

async function loadOrganization(input: {
  database: D1DatabaseLike;
  namespace: string;
  orgId: string;
}): Promise<ConsoleOrganization | null> {
  const row = await queryD1One(
    input.database,
    `SELECT *
       FROM organizations
      WHERE namespace = ?
        AND id = ?
      LIMIT 1`,
    [input.namespace, input.orgId],
  );
  return row ? parseOrgRow(row) : null;
}

async function loadProjectRow(input: {
  database: D1DatabaseLike;
  namespace: string;
  orgId: string;
  projectId: string;
}): Promise<D1Row | null> {
  return await queryD1One(
    input.database,
    `SELECT *
       FROM projects
      WHERE namespace = ?
        AND org_id = ?
        AND id = ?
      LIMIT 1`,
    [input.namespace, input.orgId, input.projectId],
  );
}

async function loadProjectWithEnvironmentCount(input: {
  database: D1DatabaseLike;
  namespace: string;
  orgId: string;
  projectId: string;
}): Promise<ConsoleProject | null> {
  const row = await queryD1One(
    input.database,
    `SELECT p.*,
            (
              SELECT COUNT(*)
                FROM environments e
               WHERE e.namespace = p.namespace
                 AND e.org_id = p.org_id
                 AND e.project_id = p.id
            ) AS environment_count
       FROM projects p
      WHERE p.namespace = ?
        AND p.org_id = ?
        AND p.id = ?
      LIMIT 1`,
    [input.namespace, input.orgId, input.projectId],
  );
  return row ? parseProjectRow(row) : null;
}

async function loadEnvironmentRow(input: {
  database: D1DatabaseLike;
  namespace: string;
  orgId: string;
  environmentId: string;
}): Promise<D1Row | null> {
  return await queryD1One(
    input.database,
    `SELECT *
       FROM environments
      WHERE namespace = ?
        AND org_id = ?
        AND id = ?
      LIMIT 1`,
    [input.namespace, input.orgId, input.environmentId],
  );
}

async function loadEnvironment(input: {
  database: D1DatabaseLike;
  namespace: string;
  orgId: string;
  environmentId: string;
}): Promise<ConsoleEnvironment | null> {
  const row = await loadEnvironmentRow(input);
  return row ? parseEnvironmentRow(row) : null;
}

async function findExistingProjectId(input: {
  database: D1DatabaseLike;
  namespace: string;
  projectId: string;
}): Promise<string | null> {
  const row = await queryD1One(
    input.database,
    `SELECT id
       FROM projects
      WHERE namespace = ?
        AND id = ?
      LIMIT 1`,
    [input.namespace, input.projectId],
  );
  return normalizeOptionalString(row?.id);
}

async function findExistingDefaultEnvironmentId(input: {
  database: D1DatabaseLike;
  namespace: string;
  projectId: string;
}): Promise<string | null> {
  const row = await queryD1One(
    input.database,
    `SELECT id
       FROM environments
      WHERE namespace = ?
        AND id IN (?, ?, ?)
      LIMIT 1`,
    [
      input.namespace,
      defaultEnvironmentId(input.projectId, 'dev'),
      defaultEnvironmentId(input.projectId, 'staging'),
      defaultEnvironmentId(input.projectId, 'prod'),
    ],
  );
  return normalizeOptionalString(row?.id);
}

async function findEnvironmentId(input: {
  database: D1DatabaseLike;
  namespace: string;
  environmentId: string;
}): Promise<string | null> {
  const row = await queryD1One(
    input.database,
    `SELECT id
       FROM environments
      WHERE namespace = ?
        AND id = ?
      LIMIT 1`,
    [input.namespace, input.environmentId],
  );
  return normalizeOptionalString(row?.id);
}

function buildDefaultEnvironmentInserts(input: {
  database: D1DatabaseLike;
  namespace: string;
  orgId: string;
  projectId: string;
  liveEnvironmentsEnabled: boolean;
  createdAtMs: number;
}): D1PreparedStatementLike[] {
  const statements: D1PreparedStatementLike[] = [];
  for (const key of DEFAULT_ENVIRONMENT_KEYS) {
    statements.push(
      input.database
        .prepare(
          `INSERT INTO environments
            (namespace, id, org_id, project_id, env_key, signing_root_version, name, status, created_at_ms, updated_at_ms)
           VALUES
            (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          input.namespace,
          defaultEnvironmentId(input.projectId, key),
          input.orgId,
          input.projectId,
          key,
          DEFAULT_CONSOLE_SIGNING_ROOT_VERSION,
          environmentNameFromKey(key),
          defaultEnvironmentStatus(key, input.liveEnvironmentsEnabled),
          input.createdAtMs,
          input.createdAtMs,
        ),
    );
  }
  return statements;
}

async function insertProjectWithDefaultEnvironments(input: {
  database: D1DatabaseLike;
  namespace: string;
  orgId: string;
  projectId: string;
  name: string;
  liveEnvironmentsEnabled: boolean;
  createdAtMs: number;
}): Promise<void> {
  const statements = [
    input.database
      .prepare(
        `INSERT INTO projects
          (namespace, id, org_id, name, slug, status, created_at_ms, updated_at_ms)
         VALUES
          (?, ?, ?, ?, ?, 'ACTIVE', ?, ?)`,
      )
      .bind(
        input.namespace,
        input.projectId,
        input.orgId,
        input.name,
        slugify(input.name),
        input.createdAtMs,
        input.createdAtMs,
      ),
    ...buildDefaultEnvironmentInserts(input),
  ];
  await input.database.batch(statements);
}

async function createProjectInD1(input: {
  database: D1DatabaseLike;
  namespace: string;
  ctx: ConsoleOrgProjectEnvContext;
  now: () => Date;
  request: CreateConsoleProjectRequest;
}): Promise<ConsoleProject> {
  const organization = await loadOrganization({
    database: input.database,
    namespace: input.namespace,
    orgId: input.ctx.orgId,
  });
  if (!organization) {
    throw new ConsoleOrgProjectEnvError(
      'organization_not_found',
      404,
      `Organization ${input.ctx.orgId} was not found`,
    );
  }

  const currentNow = input.now();
  const currentNowMs = nowMs(currentNow);
  const projectId = String(input.request.id || makeResourceId('proj', currentNow)).trim();
  const existingProjectId = await findExistingProjectId({
    database: input.database,
    namespace: input.namespace,
    projectId,
  });
  if (existingProjectId) {
    throw new ConsoleOrgProjectEnvError(
      'project_already_exists',
      409,
      `Project ${projectId} already exists`,
    );
  }

  const existingEnvironmentId = await findExistingDefaultEnvironmentId({
    database: input.database,
    namespace: input.namespace,
    projectId,
  });
  if (existingEnvironmentId) {
    throw new ConsoleOrgProjectEnvError(
      'environment_already_exists',
      409,
      `Environment ${existingEnvironmentId} already exists`,
    );
  }

  try {
    await insertProjectWithDefaultEnvironments({
      database: input.database,
      namespace: input.namespace,
      orgId: input.ctx.orgId,
      projectId,
      name: input.request.name,
      liveEnvironmentsEnabled: input.request.liveEnvironmentsEnabled === true,
      createdAtMs: currentNowMs,
    });
  } catch (error: unknown) {
    if (!isD1ConstraintError(error)) throw error;
    throw new ConsoleOrgProjectEnvError(
      'project_already_exists',
      409,
      `Project ${projectId} already exists`,
    );
  }

  const project = await loadProjectWithEnvironmentCount({
    database: input.database,
    namespace: input.namespace,
    orgId: input.ctx.orgId,
    projectId,
  });
  if (!project) {
    throw new ConsoleOrgProjectEnvError(
      'project_not_found',
      404,
      `Project ${projectId} was not found`,
    );
  }
  return project;
}

export async function createD1ConsoleOrgProjectEnvService(
  options: D1ConsoleOrgProjectEnvServiceOptions,
): Promise<ConsoleOrgProjectEnvService> {
  if (options.ensureSchema) {
    await ensureConsoleOrgProjectEnvD1Schema({ database: options.database });
  }
  const database = options.database;
  const namespace = ensureNamespace(options.namespace);
  const now = options.now || defaultNow;
  const runtime: ConsoleOrgProjectEnvD1Runtime = { database, namespace, now };

  const service: ConsoleOrgProjectEnvD1Service = {
    async getOrganization(ctx): Promise<ConsoleOrganization> {
      const organization = await loadOrganization({
        database,
        namespace,
        orgId: ctx.orgId,
      });
      if (!organization) {
        throw new ConsoleOrgProjectEnvError(
          'organization_not_found',
          404,
          `Organization ${ctx.orgId} was not found`,
        );
      }
      return organization;
    },

    async findDefaultOrganization(): Promise<ConsoleOrganization | null> {
      const rows = await queryD1All(
        database,
        `SELECT *
           FROM organizations
          WHERE namespace = ?
            AND status = 'ACTIVE'
          ORDER BY created_at_ms ASC, id ASC
          LIMIT 2`,
        [namespace],
      );
      if (rows.length !== 1) return null;
      return parseOrgRow(rows[0]!);
    },

    async searchOrganizations(
      request: SearchConsoleOrganizationsRequest,
    ): Promise<ConsoleOrganization[]> {
      const query = normalizeOrganizationSearchValue(request.query);
      const rawLimit = Number(request.limit || 0);
      const limit =
        Number.isFinite(rawLimit) && rawLimit > 0 ? Math.max(1, Math.floor(rawLimit)) : 10;
      if (!query) {
        const rows = await queryD1All(
          database,
          `SELECT *
             FROM organizations
            WHERE namespace = ?
            ORDER BY created_at_ms DESC, id ASC
            LIMIT ?`,
          [namespace, limit],
        );
        return rows.map(parseOrgRow);
      }
      const candidateLimit = Math.max(limit * 5, 25);
      const rows = await queryD1All(
        database,
        `SELECT *
           FROM organizations
          WHERE namespace = ?
            AND (
              LOWER(name) LIKE ?
              OR LOWER(id) LIKE ?
            )
          LIMIT ?`,
        [namespace, `%${query}%`, `%${query}%`, candidateLimit],
      );
      return sortOrganizationSearchResults(rows.map(parseOrgRow), query).slice(0, limit);
    },

    async findOrganizationForScope(request): Promise<ConsoleOrganization | null> {
      const projectId = String(request.projectId || '').trim();
      const environmentId = String(request.environmentId || '').trim();

      if (environmentId) {
        const values: unknown[] = [namespace, environmentId];
        let projectFilter = '';
        if (projectId) {
          values.push(projectId);
          projectFilter = ' AND e.project_id = ?';
        }
        const environmentRow = await queryD1One(
          database,
          `SELECT o.*
             FROM environments e
             JOIN organizations o
               ON o.namespace = e.namespace
              AND o.id = e.org_id
            WHERE e.namespace = ?
              AND e.id = ?${projectFilter}
            LIMIT 1`,
          values,
        );
        if (environmentRow) return parseOrgRow(environmentRow);
      }

      if (!projectId) return null;
      const projectRow = await queryD1One(
        database,
        `SELECT o.*
           FROM projects p
           JOIN organizations o
             ON o.namespace = p.namespace
            AND o.id = p.org_id
          WHERE p.namespace = ?
            AND p.id = ?
          LIMIT 1`,
        [namespace, projectId],
      );
      return projectRow ? parseOrgRow(projectRow) : null;
    },

    async upsertOrganization(
      ctx,
      request: UpsertConsoleOrganizationRequest,
    ): Promise<ConsoleOrganization> {
      const currentNow = now();
      const currentNowMs = nowMs(currentNow);
      const defaultName = humanizeId(ctx.orgId, 'Organization');
      const createdName = String(request.name || '').trim() || defaultName;
      const createdSlug = slugify(String(request.slug || '').trim() || createdName);

      await database
        .prepare(
          `INSERT INTO organizations
            (namespace, id, name, slug, created_by_user_id, status, created_at_ms, updated_at_ms)
           VALUES
            (?, ?, ?, ?, ?, 'ACTIVE', ?, ?)
           ON CONFLICT(namespace, id) DO NOTHING`,
        )
        .bind(
          namespace,
          ctx.orgId,
          createdName,
          createdSlug,
          normalizeOptionalString(ctx.actorUserId),
          currentNowMs,
          currentNowMs,
        )
        .run();

      const base = await loadOrganization({
        database,
        namespace,
        orgId: ctx.orgId,
      });
      if (!base) {
        throw new ConsoleOrgProjectEnvError(
          'organization_not_found',
          404,
          `Organization ${ctx.orgId} was not found`,
        );
      }

      const nextName = String(request.name || '').trim() || base.name || defaultName;
      const nextSlug = slugify(String(request.slug || '').trim() || base.slug || nextName);
      await database
        .prepare(
          `UPDATE organizations
              SET name = ?,
                  slug = ?,
                  updated_at_ms = ?
            WHERE namespace = ?
              AND id = ?`,
        )
        .bind(nextName, nextSlug, currentNowMs, namespace, ctx.orgId)
        .run();

      const organization = await loadOrganization({
        database,
        namespace,
        orgId: ctx.orgId,
      });
      if (!organization) {
        throw new ConsoleOrgProjectEnvError(
          'organization_not_found',
          404,
          `Organization ${ctx.orgId} was not found`,
        );
      }
      return organization;
    },

    async deleteOrganization(
      ctx,
    ): Promise<{ deleted: boolean; organization: ConsoleOrganization | null }> {
      const organization = await loadOrganization({
        database,
        namespace,
        orgId: ctx.orgId,
      });
      if (!organization) return { deleted: false, organization: null };
      await database.batch([
        database
          .prepare(
            `DELETE FROM environments
              WHERE namespace = ?
                AND org_id = ?`,
          )
          .bind(namespace, ctx.orgId),
        database
          .prepare(
            `DELETE FROM projects
              WHERE namespace = ?
                AND org_id = ?`,
          )
          .bind(namespace, ctx.orgId),
        database
          .prepare(
            `DELETE FROM organizations
              WHERE namespace = ?
                AND id = ?`,
          )
          .bind(namespace, ctx.orgId),
      ]);
      return { deleted: true, organization };
    },

    async listProjects(ctx, request?: ListConsoleProjectsRequest): Promise<ConsoleProject[]> {
      const values: unknown[] = [namespace, ctx.orgId];
      let statusFilter = '';
      if (request?.status) {
        values.push(request.status);
        statusFilter = ' AND p.status = ?';
      }
      const rows = await queryD1All(
        database,
        `SELECT p.*,
                (
                  SELECT COUNT(*)
                    FROM environments e
                   WHERE e.namespace = p.namespace
                     AND e.org_id = p.org_id
                     AND e.project_id = p.id
                ) AS environment_count
           FROM projects p
          WHERE p.namespace = ?
            AND p.org_id = ?${statusFilter}
          ORDER BY p.updated_at_ms DESC, p.created_at_ms DESC`,
        values,
      );
      return rows.map(parseProjectRow);
    },

    async createProject(
      ctx,
      request: CreateConsoleProjectRequest,
    ): Promise<ConsoleProject> {
      return await createProjectInD1({ database, namespace, ctx, now, request });
    },

    async updateProject(
      ctx,
      projectId: string,
      request: UpdateConsoleProjectRequest,
    ): Promise<ConsoleProject | null> {
      const current = await loadProjectRow({ database, namespace, orgId: ctx.orgId, projectId });
      if (!current) return null;
      if (parseProjectStatus(current.status) === 'ARCHIVED') {
        throw new ConsoleOrgProjectEnvError(
          'project_archived',
          409,
          `Project ${projectId} is archived and cannot be updated`,
        );
      }
      const nextName = request.name || String(current.name || '');
      await database
        .prepare(
          `UPDATE projects
              SET name = ?,
                  slug = ?,
                  updated_at_ms = ?
            WHERE namespace = ?
              AND org_id = ?
              AND id = ?`,
        )
        .bind(nextName, slugify(nextName), nowMs(now()), namespace, ctx.orgId, projectId)
        .run();
      return await loadProjectWithEnvironmentCount({
        database,
        namespace,
        orgId: ctx.orgId,
        projectId,
      });
    },

    async archiveProject(ctx, projectId: string): Promise<ConsoleProject | null> {
      const current = await loadProjectRow({ database, namespace, orgId: ctx.orgId, projectId });
      if (!current) return null;
      const currentNowMs = nowMs(now());
      await database.batch([
        database
          .prepare(
            `UPDATE projects
                SET status = 'ARCHIVED',
                    updated_at_ms = ?
              WHERE namespace = ?
                AND org_id = ?
                AND id = ?`,
          )
          .bind(currentNowMs, namespace, ctx.orgId, projectId),
        database
          .prepare(
            `UPDATE environments
                SET status = 'ARCHIVED',
                    updated_at_ms = ?
              WHERE namespace = ?
                AND org_id = ?
                AND project_id = ?`,
          )
          .bind(currentNowMs, namespace, ctx.orgId, projectId),
      ]);
      return await loadProjectWithEnvironmentCount({
        database,
        namespace,
        orgId: ctx.orgId,
        projectId,
      });
    },

    async listEnvironments(
      ctx,
      request?: ListConsoleEnvironmentsRequest,
    ): Promise<ConsoleEnvironment[]> {
      const values: unknown[] = [namespace, ctx.orgId];
      let projectFilter = '';
      let statusFilter = '';
      if (request?.projectId) {
        values.push(request.projectId);
        projectFilter = ' AND project_id = ?';
      }
      if (request?.status) {
        values.push(request.status);
        statusFilter = ' AND status = ?';
      }
      const rows = await queryD1All(
        database,
        `SELECT *
           FROM environments
          WHERE namespace = ?
            AND org_id = ?${projectFilter}${statusFilter}
          ORDER BY updated_at_ms DESC, created_at_ms DESC`,
        values,
      );
      const environments = rows.map(parseEnvironmentRow);
      return sortEnvironments(environments);
    },

    async createEnvironment(
      ctx,
      request: CreateConsoleEnvironmentRequest,
    ): Promise<ConsoleEnvironment> {
      const project = await loadProjectRow({
        database,
        namespace,
        orgId: ctx.orgId,
        projectId: request.projectId,
      });
      if (!project) {
        throw new ConsoleOrgProjectEnvError(
          'project_not_found',
          404,
          `Project ${request.projectId} was not found`,
        );
      }
      if (parseProjectStatus(project.status) === 'ARCHIVED') {
        throw new ConsoleOrgProjectEnvError(
          'project_archived',
          409,
          `Project ${request.projectId} is archived`,
        );
      }

      const duplicateKey = await queryD1One(
        database,
        `SELECT id
           FROM environments
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_key = ?
          LIMIT 1`,
        [namespace, ctx.orgId, request.projectId, request.key],
      );
      if (duplicateKey) {
        throw new ConsoleOrgProjectEnvError(
          'environment_key_conflict',
          409,
          `Environment key ${request.key} already exists for project ${request.projectId}`,
        );
      }

      const currentNow = now();
      const currentNowMs = nowMs(currentNow);
      const environmentId = String(request.id || makeResourceId('env', currentNow)).trim();
      const existingEnvironmentId = await findEnvironmentId({
        database,
        namespace,
        environmentId,
      });
      if (existingEnvironmentId) {
        throw new ConsoleOrgProjectEnvError(
          'environment_already_exists',
          409,
          `Environment ${environmentId} already exists`,
        );
      }

      try {
        await database
          .prepare(
            `INSERT INTO environments
              (namespace, id, org_id, project_id, env_key, signing_root_version, name, status, created_at_ms, updated_at_ms)
             VALUES
              (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          )
          .bind(
            namespace,
            environmentId,
            ctx.orgId,
            request.projectId,
            request.key,
            normalizeSigningRootVersion(
              request.signingRootVersion,
              DEFAULT_CONSOLE_SIGNING_ROOT_VERSION,
            ),
            request.name || environmentNameFromKey(request.key),
            request.status || 'ACTIVE',
            currentNowMs,
            currentNowMs,
          )
          .run();
      } catch (error: unknown) {
        if (!isD1ConstraintError(error)) throw error;
        throw new ConsoleOrgProjectEnvError(
          'environment_already_exists',
          409,
          `Environment ${environmentId} already exists`,
        );
      }

      const environment = await loadEnvironment({
        database,
        namespace,
        orgId: ctx.orgId,
        environmentId,
      });
      if (!environment) {
        throw new ConsoleOrgProjectEnvError(
          'environment_not_found',
          404,
          `Environment ${environmentId} was not found`,
        );
      }
      return environment;
    },

    async updateEnvironment(
      ctx,
      environmentId: string,
      request: UpdateConsoleEnvironmentRequest,
    ): Promise<ConsoleEnvironment | null> {
      const current = await loadEnvironmentRow({
        database,
        namespace,
        orgId: ctx.orgId,
        environmentId,
      });
      if (!current) return null;
      if (parseEnvironmentStatus(current.status) === 'ARCHIVED') {
        throw new ConsoleOrgProjectEnvError(
          'environment_archived',
          409,
          `Environment ${environmentId} is archived and cannot be updated`,
        );
      }
      const nextName = request.name || String(current.name || '');
      const nextSigningRootVersion =
        request.signingRootVersion !== undefined
          ? normalizeSigningRootVersion(request.signingRootVersion)
          : normalizeSigningRootVersion(
              current.signing_root_version,
              DEFAULT_CONSOLE_SIGNING_ROOT_VERSION,
            );
      await database
        .prepare(
          `UPDATE environments
              SET name = ?,
                  signing_root_version = ?,
                  updated_at_ms = ?
            WHERE namespace = ?
              AND org_id = ?
              AND id = ?`,
        )
        .bind(nextName, nextSigningRootVersion, nowMs(now()), namespace, ctx.orgId, environmentId)
        .run();
      return await loadEnvironment({ database, namespace, orgId: ctx.orgId, environmentId });
    },

    async archiveEnvironment(ctx, environmentId: string): Promise<ConsoleEnvironment | null> {
      const result = await database
        .prepare(
          `UPDATE environments
              SET status = 'ARCHIVED',
                  updated_at_ms = ?
            WHERE namespace = ?
              AND org_id = ?
              AND id = ?`,
        )
        .bind(nowMs(now()), namespace, ctx.orgId, environmentId)
        .run();
      if (d1ChangedRows(result) !== 1) return null;
      return await loadEnvironment({ database, namespace, orgId: ctx.orgId, environmentId });
    },

    [CONSOLE_ORG_PROJECT_ENV_D1_RUNTIME]: runtime,
  };

  return service;
}
