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
import { ConsoleOrgProjectEnvError } from './errors';
import type {
  CreateConsoleEnvironmentRequest,
  CreateConsoleProjectRequest,
  ConsoleEnvironment,
  ConsoleOrganization,
  ConsoleProject,
  ListConsoleProjectsRequest,
  ListConsoleEnvironmentsRequest,
  UpsertConsoleOrganizationRequest,
  UpdateConsoleEnvironmentRequest,
  UpdateConsoleProjectRequest,
} from './types';
import type { ConsoleOrgProjectEnvContext, ConsoleOrgProjectEnvService } from './service';

type PgPool = Awaited<ReturnType<typeof getPostgresPool>>;
type Queryable = Pick<PgPool, 'query'>;
type PgRow = Record<string, unknown>;

const CONSOLE_ORG_PROJECT_ENV_MIGRATION_LOCK_ID = 9452360123586;

function nowMs(now: Date): number {
  return now.getTime();
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

function environmentNameFromKey(key: 'dev' | 'staging' | 'prod'): string {
  if (key === 'dev') return 'Development';
  if (key === 'staging') return 'Staging';
  return 'Production';
}

function defaultEnvironmentStatus(
  key: ConsoleEnvironment['key'],
  liveEnvironmentsEnabled: boolean,
): Exclude<ConsoleEnvironment['status'], 'ARCHIVED'> {
  if (key === 'dev') return 'ACTIVE';
  return liveEnvironmentsEnabled ? 'ACTIVE' : 'DISABLED';
}

function defaultEnvironmentId(projectId: string, key: ConsoleEnvironment['key']): string {
  return `${projectId}:${key}`;
}

function makeResourceId(prefix: string, now: Date): string {
  return `${prefix}_${now.getTime().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
}

function parseOrgRow(row: PgRow): ConsoleOrganization {
  return {
    id: String(row.id || ''),
    name: String(row.name || ''),
    slug: String(row.slug || ''),
    status: 'ACTIVE',
    createdAt: toIso(toNumber(row.created_at_ms)) || new Date(0).toISOString(),
    updatedAt: toIso(toNumber(row.updated_at_ms)) || new Date(0).toISOString(),
  };
}

function parseProjectRow(row: PgRow): ConsoleProject {
  return {
    id: String(row.id || ''),
    orgId: String(row.org_id || ''),
    name: String(row.name || ''),
    slug: String(row.slug || ''),
    status: String(row.status || 'ACTIVE') as ConsoleProject['status'],
    environmentCount: toNumber(row.environment_count, 0),
    createdAt: toIso(toNumber(row.created_at_ms)) || new Date(0).toISOString(),
    updatedAt: toIso(toNumber(row.updated_at_ms)) || new Date(0).toISOString(),
  };
}

function parseEnvironmentRow(row: PgRow): ConsoleEnvironment {
  return {
    id: String(row.id || ''),
    orgId: String(row.org_id || ''),
    projectId: String(row.project_id || ''),
    key: String(row.env_key || 'prod') as ConsoleEnvironment['key'],
    name: String(row.name || ''),
    status: String(row.status || 'ACTIVE') as ConsoleEnvironment['status'],
    createdAt: toIso(toNumber(row.created_at_ms)) || new Date(0).toISOString(),
    updatedAt: toIso(toNumber(row.updated_at_ms)) || new Date(0).toISOString(),
  };
}

async function queryOne(q: Queryable, text: string, values: unknown[]): Promise<PgRow | null> {
  const out = await q.query(text, values);
  return (out.rows[0] as PgRow) || null;
}

async function queryProjectWithEnvironmentCount(
  q: Queryable,
  input: {
    namespace: string;
    orgId: string;
    projectId: string;
  },
): Promise<ConsoleProject | null> {
  const row = await queryOne(
    q,
    `SELECT p.*,
            COALESCE(ec.environment_count, 0) AS environment_count
       FROM console_projects p
       LEFT JOIN (
         SELECT namespace,
                org_id,
                project_id,
                COUNT(*)::BIGINT AS environment_count
           FROM console_environments
          WHERE namespace = $1
            AND org_id = $2
            AND project_id = $3
          GROUP BY namespace, org_id, project_id
       ) ec
         ON ec.namespace = p.namespace
        AND ec.org_id = p.org_id
        AND ec.project_id = p.id
      WHERE p.namespace = $1
        AND p.org_id = $2
        AND p.id = $3`,
    [input.namespace, input.orgId, input.projectId],
  );
  return row ? parseProjectRow(row) : null;
}

export interface PostgresConsoleOrgProjectEnvSchemaOptions {
  postgresUrl: string;
  logger: NormalizedLogger;
}

export async function ensureConsoleOrgProjectEnvPostgresSchema(
  options: PostgresConsoleOrgProjectEnvSchemaOptions,
): Promise<void> {
  const pool = await getPostgresPool(options.postgresUrl);
  await pool.query('SELECT pg_advisory_lock($1)', [CONSOLE_ORG_PROJECT_ENV_MIGRATION_LOCK_ID]);
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_organizations (
        namespace TEXT NOT NULL,
        id TEXT NOT NULL,
        name TEXT NOT NULL,
        slug TEXT NOT NULL,
        created_by_user_id TEXT,
        status TEXT NOT NULL,
        created_at_ms BIGINT NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, id),
        CHECK (status IN ('ACTIVE'))
      )
    `);
    await pool.query(`
      ALTER TABLE console_organizations
      ADD COLUMN IF NOT EXISTS created_by_user_id TEXT
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_projects (
        namespace TEXT NOT NULL,
        id TEXT NOT NULL,
        org_id TEXT NOT NULL,
        name TEXT NOT NULL,
        slug TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at_ms BIGINT NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, id),
        CHECK (status IN ('ACTIVE', 'ARCHIVED')),
        FOREIGN KEY (namespace, org_id)
          REFERENCES console_organizations(namespace, id)
          ON DELETE CASCADE
      )
    `);
    await pool.query(`
      ALTER TABLE console_projects
      DROP CONSTRAINT IF EXISTS console_projects_status_check
    `);
    await pool.query(`
      DO $$
      BEGIN
        ALTER TABLE console_projects
          ADD CONSTRAINT console_projects_status_check
          CHECK (status IN ('ACTIVE', 'ARCHIVED'));
      EXCEPTION
        WHEN duplicate_object THEN NULL;
      END
      $$;
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_projects_org_updated_idx
      ON console_projects (namespace, org_id, updated_at_ms DESC, created_at_ms DESC)
    `);
    await pool.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS console_projects_namespace_id_org_unique_idx
      ON console_projects (namespace, id, org_id)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_environments (
        namespace TEXT NOT NULL,
        id TEXT NOT NULL,
        org_id TEXT NOT NULL,
        project_id TEXT NOT NULL,
        env_key TEXT NOT NULL,
        name TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at_ms BIGINT NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, id),
        CHECK (status IN ('ACTIVE', 'DISABLED', 'ARCHIVED')),
        CHECK (env_key IN ('dev', 'staging', 'prod')),
        UNIQUE (namespace, project_id, env_key),
        FOREIGN KEY (namespace, project_id, org_id)
          REFERENCES console_projects(namespace, id, org_id)
          ON DELETE CASCADE
      )
    `);
    await pool.query(`
      ALTER TABLE console_environments
      DROP CONSTRAINT IF EXISTS console_environments_status_check
    `);
    await pool.query(`
      DO $$
      BEGIN
        ALTER TABLE console_environments
          ADD CONSTRAINT console_environments_status_check
          CHECK (status IN ('ACTIVE', 'DISABLED', 'ARCHIVED'));
      EXCEPTION
        WHEN duplicate_object THEN NULL;
      END
      $$;
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_environments_org_project_updated_idx
      ON console_environments (namespace, org_id, project_id, updated_at_ms DESC, created_at_ms DESC)
    `);
    await pool.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS console_environments_namespace_id_project_org_unique_idx
      ON console_environments (namespace, id, project_id, org_id)
    `);
    await pool.query(`
      ALTER TABLE console_environments
      DROP CONSTRAINT IF EXISTS console_environments_namespace_project_id_fkey
    `);
    await pool.query(`
      DO $$
      BEGIN
        ALTER TABLE console_environments
          ADD CONSTRAINT console_environments_project_org_fk
          FOREIGN KEY (namespace, project_id, org_id)
          REFERENCES console_projects(namespace, id, org_id)
          ON DELETE CASCADE;
      EXCEPTION
        WHEN duplicate_object THEN NULL;
      END
      $$;
    `);

    await ensureConsoleTenantRlsPolicies({
      q: pool,
      table: 'console_organizations',
      policyName: 'console_organizations_tenant_rls',
      orgIdColumn: 'id',
    });
    await ensureConsoleTenantRlsPolicies({
      q: pool,
      table: 'console_projects',
      policyName: 'console_projects_tenant_rls',
    });
    await ensureConsoleTenantRlsPolicies({
      q: pool,
      table: 'console_environments',
      policyName: 'console_environments_tenant_rls',
    });
  } finally {
    try {
      await pool.query('SELECT pg_advisory_unlock($1)', [CONSOLE_ORG_PROJECT_ENV_MIGRATION_LOCK_ID]);
    } catch {
      // no-op
    }
  }
  options.logger.info('[console-org-project-env][postgres] Schema ready');
}

export interface PostgresConsoleOrgProjectEnvServiceOptions {
  postgresUrl: string;
  namespace?: string;
  logger?: NormalizedLogger;
  ensureSchema?: boolean;
  now?: () => Date;
}

export async function createPostgresConsoleOrgProjectEnvService(
  options: PostgresConsoleOrgProjectEnvServiceOptions,
): Promise<ConsoleOrgProjectEnvService> {
  const postgresUrl = String(options.postgresUrl || '').trim();
  if (!postgresUrl) {
    throw new Error('Missing POSTGRES_URL for Postgres console org/project/environment service');
  }

  const namespace = ensureNamespace(options.namespace);
  const logger = options.logger || console;
  const nowFn = options.now || (() => new Date());

  if (options.ensureSchema !== false) {
    await ensureConsoleOrgProjectEnvPostgresSchema({
      postgresUrl,
      logger: logger as NormalizedLogger,
    });
  }
  const pool = await getPostgresPool(postgresUrl);
  const withTenantTx = <T>(
    ctx: ConsoleOrgProjectEnvContext,
    fn: (q: Queryable) => Promise<T>,
  ): Promise<T> => withConsoleTenantContextTx(pool, { namespace, orgId: ctx.orgId }, fn);

  return {
    async getOrganization(ctx): Promise<ConsoleOrganization> {
      return withTenantTx(ctx, async (q) => {
        const row = await queryOne(
          q,
          `SELECT *
             FROM console_organizations
            WHERE namespace = $1 AND id = $2`,
          [namespace, ctx.orgId],
        );
        if (!row) {
          throw new ConsoleOrgProjectEnvError(
            'organization_not_found',
            404,
            `Organization ${ctx.orgId} was not found`,
          );
        }
        return parseOrgRow(row);
      });
    },

    async upsertOrganization(
      ctx,
      request: UpsertConsoleOrganizationRequest,
    ): Promise<ConsoleOrganization> {
      return withTenantTx(ctx, async (q) => {
        const now = nowFn();
        const current = await queryOne(
          q,
          `SELECT *
             FROM console_organizations
            WHERE namespace = $1 AND id = $2`,
          [namespace, ctx.orgId],
        );
        if (!current) {
          const defaultName = humanizeId(ctx.orgId, 'Organization');
          const created = await queryOne(
            q,
            `INSERT INTO console_organizations
              (namespace, id, name, slug, created_by_user_id, status, created_at_ms, updated_at_ms)
             VALUES
              ($1, $2, $3, $4, $5, 'ACTIVE', $6, $6)
             ON CONFLICT (namespace, id) DO NOTHING
             RETURNING *`,
            [
              namespace,
              ctx.orgId,
              String(request.name || '').trim() || defaultName,
              slugify(String(request.slug || '').trim() || String(request.name || '').trim() || defaultName),
              String(ctx.actorUserId || '').trim() || null,
              nowMs(now),
            ],
          );
          if (created) return parseOrgRow(created);
        }
        const refreshed = await queryOne(
          q,
          `SELECT *
             FROM console_organizations
            WHERE namespace = $1 AND id = $2`,
          [namespace, ctx.orgId],
        );
        const base = refreshed || current;
        if (!base) {
          throw new ConsoleOrgProjectEnvError(
            'organization_not_found',
            404,
            `Organization ${ctx.orgId} was not found`,
          );
        }
        const nextName = String(request.name || '').trim() || String(base.name || '');
        const nextSlug =
          slugify(
            String(request.slug || '').trim() ||
              String(base.slug || '') ||
              nextName ||
              humanizeId(ctx.orgId, 'Organization'),
          );
        const updated = await queryOne(
          q,
          `UPDATE console_organizations
              SET name = $3,
                  slug = $4,
                  updated_at_ms = $5
            WHERE namespace = $1 AND id = $2
            RETURNING *`,
          [namespace, ctx.orgId, nextName, nextSlug, nowMs(now)],
        );
        if (!updated) {
          throw new ConsoleOrgProjectEnvError(
            'organization_not_found',
            404,
            `Organization ${ctx.orgId} was not found`,
          );
        }
        return parseOrgRow(updated);
      });
    },

    async deleteOrganization(
      ctx,
    ): Promise<{ deleted: boolean; organization: ConsoleOrganization | null }> {
      return withTenantTx(ctx, async (q) => {
        const row = await queryOne(
          q,
          `DELETE FROM console_organizations
            WHERE namespace = $1
              AND id = $2
          RETURNING *`,
          [namespace, ctx.orgId],
        );
        return {
          deleted: Boolean(row),
          organization: row ? parseOrgRow(row) : null,
        };
      });
    },

    async listProjects(
      ctx,
      request?: ListConsoleProjectsRequest,
    ): Promise<ConsoleProject[]> {
      return withTenantTx(ctx, async (q) => {
        const where: string[] = ['p.namespace = $1', 'p.org_id = $2'];
        const values: unknown[] = [namespace, ctx.orgId];
        if (request?.status) {
          values.push(request.status);
          where.push(`p.status = $${values.length}`);
        }
        const out = await q.query(
          `SELECT p.*,
                  COALESCE(ec.environment_count, 0) AS environment_count
             FROM console_projects p
             LEFT JOIN (
               SELECT namespace,
                      org_id,
                      project_id,
                      COUNT(*)::BIGINT AS environment_count
                 FROM console_environments
                WHERE namespace = $1
                  AND org_id = $2
                GROUP BY namespace, org_id, project_id
             ) ec
               ON ec.namespace = p.namespace
              AND ec.org_id = p.org_id
              AND ec.project_id = p.id
            WHERE ${where.join(' AND ')}
            ORDER BY p.updated_at_ms DESC, p.created_at_ms DESC`,
          values,
        );
        return out.rows.map((row) => parseProjectRow(row as PgRow));
      });
    },

    async createProject(
      ctx,
      request: CreateConsoleProjectRequest,
    ): Promise<ConsoleProject> {
      return withTenantTx(ctx, async (q) => {
        const now = nowFn();
        const org = await queryOne(
          q,
          `SELECT id
             FROM console_organizations
            WHERE namespace = $1 AND id = $2`,
          [namespace, ctx.orgId],
        );
        if (!org) {
          throw new ConsoleOrgProjectEnvError(
            'organization_not_found',
            404,
            `Organization ${ctx.orgId} was not found`,
          );
        }
        const projectId = String(request.id || makeResourceId('proj', now)).trim();
        const created = await queryOne(
          q,
          `INSERT INTO console_projects
            (namespace, id, org_id, name, slug, status, created_at_ms, updated_at_ms)
           VALUES
            ($1, $2, $3, $4, $5, 'ACTIVE', $6, $6)
           ON CONFLICT (namespace, id) DO NOTHING
           RETURNING *`,
          [namespace, projectId, ctx.orgId, request.name, slugify(request.name), nowMs(now)],
        );
        if (!created) {
          throw new ConsoleOrgProjectEnvError(
            'project_already_exists',
            409,
            `Project ${projectId} already exists`,
          );
        }
        const liveEnvironmentsEnabled = request.liveEnvironmentsEnabled === true;
        for (const key of ['dev', 'staging', 'prod'] as const) {
          const environmentId = defaultEnvironmentId(projectId, key);
          const environment = await queryOne(
            q,
            `INSERT INTO console_environments
              (namespace, id, org_id, project_id, env_key, name, status, created_at_ms, updated_at_ms)
             VALUES
              ($1, $2, $3, $4, $5, $6, $7, $8, $8)
             ON CONFLICT (namespace, id) DO NOTHING
             RETURNING id`,
            [
              namespace,
              environmentId,
              ctx.orgId,
              projectId,
              key,
              environmentNameFromKey(key),
              defaultEnvironmentStatus(key, liveEnvironmentsEnabled),
              nowMs(now),
            ],
          );
          if (!environment) {
            throw new ConsoleOrgProjectEnvError(
              'environment_already_exists',
              409,
              `Environment ${environmentId} already exists`,
            );
          }
        }
        return (
          (await queryProjectWithEnvironmentCount(q, {
            namespace,
            orgId: ctx.orgId,
            projectId,
          })) || parseProjectRow(created)
        );
      });
    },

    async updateProject(
      ctx,
      projectId: string,
      request: UpdateConsoleProjectRequest,
    ): Promise<ConsoleProject | null> {
      return withTenantTx(ctx, async (q) => {
        const now = nowFn();
        const current = await queryOne(
          q,
          `SELECT *
             FROM console_projects
            WHERE namespace = $1 AND org_id = $2 AND id = $3`,
          [namespace, ctx.orgId, projectId],
        );
        if (!current) return null;
        if (String(current.status || '') === 'ARCHIVED') {
          throw new ConsoleOrgProjectEnvError(
            'project_archived',
            409,
            `Project ${projectId} is archived and cannot be updated`,
          );
        }
        const updated = await queryOne(
          q,
          `UPDATE console_projects
              SET name = $4,
                  slug = $5,
                  updated_at_ms = $6
            WHERE namespace = $1 AND org_id = $2 AND id = $3
            RETURNING *`,
          [
            namespace,
            ctx.orgId,
            projectId,
            request.name || String(current.name || ''),
            slugify(request.name || String(current.name || '')),
            nowMs(now),
          ],
        );
        if (!updated) return null;
        return (
          (await queryProjectWithEnvironmentCount(q, {
            namespace,
            orgId: ctx.orgId,
            projectId,
          })) || parseProjectRow(updated)
        );
      });
    },

    async archiveProject(
      ctx,
      projectId: string,
    ): Promise<ConsoleProject | null> {
      return withTenantTx(ctx, async (q) => {
        const now = nowFn();
        const current = await queryOne(
          q,
          `SELECT *
             FROM console_projects
            WHERE namespace = $1 AND org_id = $2 AND id = $3`,
          [namespace, ctx.orgId, projectId],
        );
        if (!current) return null;
        await q.query(
          `UPDATE console_projects
              SET status = 'ARCHIVED',
                  updated_at_ms = $4
            WHERE namespace = $1 AND org_id = $2 AND id = $3`,
          [namespace, ctx.orgId, projectId, nowMs(now)],
        );
        await q.query(
          `UPDATE console_environments
              SET status = 'ARCHIVED',
                  updated_at_ms = $4
            WHERE namespace = $1 AND org_id = $2 AND project_id = $3`,
          [namespace, ctx.orgId, projectId, nowMs(now)],
        );
        const archived = await queryOne(
          q,
          `SELECT *
             FROM console_projects
            WHERE namespace = $1 AND org_id = $2 AND id = $3`,
          [namespace, ctx.orgId, projectId],
        );
        if (!archived) return null;
        return (
          (await queryProjectWithEnvironmentCount(q, {
            namespace,
            orgId: ctx.orgId,
            projectId,
          })) || parseProjectRow(archived)
        );
      });
    },

    async listEnvironments(
      ctx,
      request?: ListConsoleEnvironmentsRequest,
    ): Promise<ConsoleEnvironment[]> {
      return withTenantTx(ctx, async (q) => {
        const where: string[] = ['namespace = $1', 'org_id = $2'];
        const values: unknown[] = [namespace, ctx.orgId];
        if (request?.projectId) {
          values.push(request.projectId);
          where.push(`project_id = $${values.length}`);
        }
        if (request?.status) {
          values.push(request.status);
          where.push(`status = $${values.length}`);
        }
        const out = await q.query(
          `SELECT *
             FROM console_environments
            WHERE ${where.join(' AND ')}
            ORDER BY updated_at_ms DESC, created_at_ms DESC`,
          values,
        );
        return out.rows.map((row) => parseEnvironmentRow(row as PgRow));
      });
    },

    async createEnvironment(
      ctx,
      request: CreateConsoleEnvironmentRequest,
    ): Promise<ConsoleEnvironment> {
      return withTenantTx(ctx, async (q) => {
        const now = nowFn();

        const project = await queryOne(
          q,
          `SELECT *
             FROM console_projects
            WHERE namespace = $1 AND org_id = $2 AND id = $3`,
          [namespace, ctx.orgId, request.projectId],
        );
        if (!project) {
          throw new ConsoleOrgProjectEnvError(
            'project_not_found',
            404,
            `Project ${request.projectId} was not found`,
          );
        }
        if (String(project.status || '') === 'ARCHIVED') {
          throw new ConsoleOrgProjectEnvError(
            'project_archived',
            409,
            `Project ${request.projectId} is archived`,
          );
        }

        const duplicateKey = await queryOne(
          q,
          `SELECT id
             FROM console_environments
            WHERE namespace = $1 AND org_id = $2 AND project_id = $3 AND env_key = $4`,
          [namespace, ctx.orgId, request.projectId, request.key],
        );
        if (duplicateKey) {
          throw new ConsoleOrgProjectEnvError(
            'environment_key_conflict',
            409,
            `Environment key ${request.key} already exists for project ${request.projectId}`,
          );
        }

        const environmentId = String(request.id || makeResourceId('env', now)).trim();
        const created = await queryOne(
          q,
          `INSERT INTO console_environments
            (namespace, id, org_id, project_id, env_key, name, status, created_at_ms, updated_at_ms)
           VALUES
            ($1, $2, $3, $4, $5, $6, $7, $8, $8)
           ON CONFLICT (namespace, id) DO NOTHING
           RETURNING *`,
          [
            namespace,
            environmentId,
            ctx.orgId,
            request.projectId,
            request.key,
            request.name || environmentNameFromKey(request.key),
            request.status || 'ACTIVE',
            nowMs(now),
          ],
        );
        if (!created) {
          throw new ConsoleOrgProjectEnvError(
            'environment_already_exists',
            409,
            `Environment ${environmentId} already exists`,
          );
        }
        return parseEnvironmentRow(created);
      });
    },

    async updateEnvironment(
      ctx,
      environmentId: string,
      request: UpdateConsoleEnvironmentRequest,
    ): Promise<ConsoleEnvironment | null> {
      return withTenantTx(ctx, async (q) => {
        const now = nowFn();
        const current = await queryOne(
          q,
          `SELECT *
             FROM console_environments
            WHERE namespace = $1 AND org_id = $2 AND id = $3`,
          [namespace, ctx.orgId, environmentId],
        );
        if (!current) return null;
        if (String(current.status || '') === 'ARCHIVED') {
          throw new ConsoleOrgProjectEnvError(
            'environment_archived',
            409,
            `Environment ${environmentId} is archived and cannot be updated`,
          );
        }
        const updated = await queryOne(
          q,
          `UPDATE console_environments
              SET name = $4,
                  updated_at_ms = $5
            WHERE namespace = $1 AND org_id = $2 AND id = $3
            RETURNING *`,
          [
            namespace,
            ctx.orgId,
            environmentId,
            request.name || String(current.name || ''),
            nowMs(now),
          ],
        );
        return updated ? parseEnvironmentRow(updated) : null;
      });
    },

    async archiveEnvironment(
      ctx,
      environmentId: string,
    ): Promise<ConsoleEnvironment | null> {
      return withTenantTx(ctx, async (q) => {
        const now = nowFn();
        const updated = await queryOne(
          q,
          `UPDATE console_environments
              SET status = 'ARCHIVED',
                  updated_at_ms = $4
            WHERE namespace = $1 AND org_id = $2 AND id = $3
            RETURNING *`,
          [namespace, ctx.orgId, environmentId, nowMs(now)],
        );
        return updated ? parseEnvironmentRow(updated) : null;
      });
    },
  };
}
