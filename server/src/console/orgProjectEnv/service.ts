import { ConsoleOrgProjectEnvError } from './errors';
import type {
  CreateConsoleEnvironmentRequest,
  CreateConsoleProjectRequest,
  ConsoleEnvironment,
  ConsoleOrganization,
  ConsoleProject,
  ListConsoleProjectsRequest,
  ListConsoleEnvironmentsRequest,
  UpdateConsoleEnvironmentRequest,
  UpdateConsoleProjectRequest,
} from './types';

export interface ConsoleOrgProjectEnvContext {
  orgId: string;
  actorUserId: string;
  roles: string[];
  projectId?: string;
  environmentId?: string;
}

export interface ConsoleOrgProjectEnvService {
  getOrganization(ctx: ConsoleOrgProjectEnvContext): Promise<ConsoleOrganization>;
  listProjects(
    ctx: ConsoleOrgProjectEnvContext,
    request?: ListConsoleProjectsRequest,
  ): Promise<ConsoleProject[]>;
  createProject(
    ctx: ConsoleOrgProjectEnvContext,
    request: CreateConsoleProjectRequest,
  ): Promise<ConsoleProject>;
  updateProject(
    ctx: ConsoleOrgProjectEnvContext,
    projectId: string,
    request: UpdateConsoleProjectRequest,
  ): Promise<ConsoleProject | null>;
  archiveProject(
    ctx: ConsoleOrgProjectEnvContext,
    projectId: string,
  ): Promise<ConsoleProject | null>;
  listEnvironments(
    ctx: ConsoleOrgProjectEnvContext,
    request?: ListConsoleEnvironmentsRequest,
  ): Promise<ConsoleEnvironment[]>;
  createEnvironment(
    ctx: ConsoleOrgProjectEnvContext,
    request: CreateConsoleEnvironmentRequest,
  ): Promise<ConsoleEnvironment>;
  updateEnvironment(
    ctx: ConsoleOrgProjectEnvContext,
    environmentId: string,
    request: UpdateConsoleEnvironmentRequest,
  ): Promise<ConsoleEnvironment | null>;
  archiveEnvironment(
    ctx: ConsoleOrgProjectEnvContext,
    environmentId: string,
  ): Promise<ConsoleEnvironment | null>;
}

export interface InMemoryConsoleOrgProjectEnvServiceOptions {
  now?: () => Date;
}

interface OrgStore {
  org: ConsoleOrganization;
  projects: Map<string, ConsoleProject>;
  environments: Map<string, ConsoleEnvironment>;
}

function toIso(date: Date): string {
  return date.toISOString();
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

function inferEnvironmentKey(
  environmentId: string | undefined,
): 'dev' | 'staging' | 'prod' {
  const value = String(environmentId || '').toLowerCase();
  if (value.includes('stag')) return 'staging';
  if (value.includes('dev') || value.includes('test')) return 'dev';
  return 'prod';
}

function environmentNameFromKey(key: 'dev' | 'staging' | 'prod'): string {
  if (key === 'dev') return 'Development';
  if (key === 'staging') return 'Staging';
  return 'Production';
}

function makeResourceId(prefix: string, now: Date): string {
  return `${prefix}_${now.getTime().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
}

function sortProjects(items: ConsoleProject[]): ConsoleProject[] {
  return [...items].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
}

function sortEnvironments(items: ConsoleEnvironment[]): ConsoleEnvironment[] {
  const rank = (key: ConsoleEnvironment['key']): number => {
    if (key === 'prod') return 0;
    if (key === 'staging') return 1;
    return 2;
  };
  return [...items].sort((a, b) => {
    const keyRankDiff = rank(a.key) - rank(b.key);
    if (keyRankDiff !== 0) return keyRankDiff;
    return b.updatedAt.localeCompare(a.updatedAt);
  });
}

function cloneOrg(org: ConsoleOrganization): ConsoleOrganization {
  return { ...org };
}

function cloneProject(project: ConsoleProject): ConsoleProject {
  return { ...project };
}

function cloneEnvironment(environment: ConsoleEnvironment): ConsoleEnvironment {
  return { ...environment };
}

function countEnvironmentsForProject(store: OrgStore, projectId: string): number {
  let count = 0;
  for (const environment of store.environments.values()) {
    if (environment.projectId !== projectId) continue;
    count += 1;
  }
  return count;
}

export function createInMemoryConsoleOrgProjectEnvService(
  opts: InMemoryConsoleOrgProjectEnvServiceOptions = {},
): ConsoleOrgProjectEnvService {
  const now = opts.now || (() => new Date());
  const stores = new Map<string, OrgStore>();

  function ensureOrgStore(ctx: ConsoleOrgProjectEnvContext): OrgStore {
    let store = stores.get(ctx.orgId);
    if (!store) {
      const currentNow = now();
      const createdAt = toIso(currentNow);
      store = {
        org: {
          id: ctx.orgId,
          name: humanizeId(ctx.orgId, 'Organization'),
          slug: slugify(ctx.orgId),
          status: 'ACTIVE',
          createdAt,
          updatedAt: createdAt,
        },
        projects: new Map<string, ConsoleProject>(),
        environments: new Map<string, ConsoleEnvironment>(),
      };
      stores.set(ctx.orgId, store);
    }

    const currentNow = now();
    const projectId = String(ctx.projectId || `${ctx.orgId}:default-project`).trim();
    if (projectId && !store.projects.has(projectId)) {
      const ts = toIso(currentNow);
      store.projects.set(projectId, {
        id: projectId,
        orgId: ctx.orgId,
        name: humanizeId(ctx.projectId || 'default project', 'Default Project'),
        slug: slugify(projectId),
        status: 'ACTIVE',
        environmentCount: 0,
        createdAt: ts,
        updatedAt: ts,
      });
    }

    const envKey = inferEnvironmentKey(ctx.environmentId);
    const environmentId = String(ctx.environmentId || `${projectId}:${envKey}`).trim();
    if (environmentId && !store.environments.has(environmentId)) {
      const ts = toIso(currentNow);
      store.environments.set(environmentId, {
        id: environmentId,
        orgId: ctx.orgId,
        projectId,
        key: envKey,
        name: environmentNameFromKey(envKey),
        status: 'ACTIVE',
        createdAt: ts,
        updatedAt: ts,
      });
    }

    return store;
  }

  return {
    async getOrganization(ctx): Promise<ConsoleOrganization> {
      const store = ensureOrgStore(ctx);
      return cloneOrg(store.org);
    },

    async listProjects(
      ctx,
      request?: ListConsoleProjectsRequest,
    ): Promise<ConsoleProject[]> {
      const store = ensureOrgStore(ctx);
      const rows = Array.from(store.projects.values()).filter(
        (project) => !request?.status || project.status === request.status,
      );
      return sortProjects(rows).map((project) =>
        cloneProject({
          ...project,
          environmentCount: countEnvironmentsForProject(store, project.id),
        }),
      );
    },

    async createProject(
      ctx,
      request: CreateConsoleProjectRequest,
    ): Promise<ConsoleProject> {
      const store = ensureOrgStore(ctx);
      const currentNow = now();
      const projectId = String(request.id || makeResourceId('proj', currentNow)).trim();
      if (store.projects.has(projectId)) {
        throw new ConsoleOrgProjectEnvError(
          'project_already_exists',
          409,
          `Project ${projectId} already exists`,
        );
      }
      const ts = toIso(currentNow);
      const project: ConsoleProject = {
        id: projectId,
        orgId: ctx.orgId,
        name: request.name,
        slug: slugify(request.name),
        status: 'ACTIVE',
        environmentCount: 0,
        createdAt: ts,
        updatedAt: ts,
      };
      store.projects.set(projectId, project);
      return cloneProject(project);
    },

    async updateProject(
      ctx,
      projectId: string,
      request: UpdateConsoleProjectRequest,
    ): Promise<ConsoleProject | null> {
      const store = ensureOrgStore(ctx);
      const current = store.projects.get(projectId);
      if (!current) return null;
      if (current.status === 'ARCHIVED') {
        throw new ConsoleOrgProjectEnvError(
          'project_archived',
          409,
          `Project ${projectId} is archived and cannot be updated`,
        );
      }
      const currentNow = now();
      if (request.name) {
        current.name = request.name;
        current.slug = slugify(request.name);
      }
      current.updatedAt = toIso(currentNow);
      return cloneProject({
        ...current,
        environmentCount: countEnvironmentsForProject(store, current.id),
      });
    },

    async archiveProject(
      ctx,
      projectId: string,
    ): Promise<ConsoleProject | null> {
      const store = ensureOrgStore(ctx);
      const current = store.projects.get(projectId);
      if (!current) return null;
      const currentNow = now();
      const ts = toIso(currentNow);
      current.status = 'ARCHIVED';
      current.updatedAt = ts;
      for (const env of store.environments.values()) {
        if (env.projectId !== projectId) continue;
        env.status = 'ARCHIVED';
        env.updatedAt = ts;
      }
      return cloneProject({
        ...current,
        environmentCount: countEnvironmentsForProject(store, current.id),
      });
    },

    async listEnvironments(
      ctx,
      request?: ListConsoleEnvironmentsRequest,
    ): Promise<ConsoleEnvironment[]> {
      const store = ensureOrgStore(ctx);
      const filtered = Array.from(store.environments.values()).filter(
        (entry) =>
          (!request?.projectId || entry.projectId === request.projectId) &&
          (!request?.status || entry.status === request.status),
      );
      return sortEnvironments(filtered).map(cloneEnvironment);
    },

    async createEnvironment(
      ctx,
      request: CreateConsoleEnvironmentRequest,
    ): Promise<ConsoleEnvironment> {
      const store = ensureOrgStore(ctx);
      const project = store.projects.get(request.projectId);
      if (!project) {
        throw new ConsoleOrgProjectEnvError(
          'project_not_found',
          404,
          `Project ${request.projectId} was not found`,
        );
      }
      if (project.status === 'ARCHIVED') {
        throw new ConsoleOrgProjectEnvError(
          'project_archived',
          409,
          `Project ${request.projectId} is archived`,
        );
      }
      const duplicateKey = Array.from(store.environments.values()).find(
        (entry) => entry.projectId === request.projectId && entry.key === request.key,
      );
      if (duplicateKey) {
        throw new ConsoleOrgProjectEnvError(
          'environment_key_conflict',
          409,
          `Environment key ${request.key} already exists for project ${request.projectId}`,
        );
      }
      const currentNow = now();
      const environmentId = String(request.id || makeResourceId('env', currentNow)).trim();
      if (store.environments.has(environmentId)) {
        throw new ConsoleOrgProjectEnvError(
          'environment_already_exists',
          409,
          `Environment ${environmentId} already exists`,
        );
      }
      const ts = toIso(currentNow);
      const environment: ConsoleEnvironment = {
        id: environmentId,
        orgId: ctx.orgId,
        projectId: request.projectId,
        key: request.key,
        name: request.name || environmentNameFromKey(request.key),
        status: 'ACTIVE',
        createdAt: ts,
        updatedAt: ts,
      };
      store.environments.set(environment.id, environment);
      return cloneEnvironment(environment);
    },

    async updateEnvironment(
      ctx,
      environmentId: string,
      request: UpdateConsoleEnvironmentRequest,
    ): Promise<ConsoleEnvironment | null> {
      const store = ensureOrgStore(ctx);
      const current = store.environments.get(environmentId);
      if (!current) return null;
      if (current.status === 'ARCHIVED') {
        throw new ConsoleOrgProjectEnvError(
          'environment_archived',
          409,
          `Environment ${environmentId} is archived and cannot be updated`,
        );
      }
      if (request.name) {
        current.name = request.name;
      }
      current.updatedAt = toIso(now());
      return cloneEnvironment(current);
    },

    async archiveEnvironment(
      ctx,
      environmentId: string,
    ): Promise<ConsoleEnvironment | null> {
      const store = ensureOrgStore(ctx);
      const current = store.environments.get(environmentId);
      if (!current) return null;
      current.status = 'ARCHIVED';
      current.updatedAt = toIso(now());
      return cloneEnvironment(current);
    },
  };
}
