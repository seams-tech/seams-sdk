import { ConsoleOrgProjectEnvError } from './errors';
import { DEFAULT_CONSOLE_SIGNING_ROOT_VERSION } from './types';
import type {
  CreateConsoleEnvironmentRequest,
  CreateConsoleProjectRequest,
  ConsoleEnvironment,
  ConsoleOrganization,
  ConsoleProject,
  ListConsoleProjectsRequest,
  ListConsoleEnvironmentsRequest,
  SearchConsoleOrganizationsRequest,
  UpsertConsoleOrganizationRequest,
  UpdateConsoleEnvironmentRequest,
  UpdateConsoleProjectRequest,
} from './types';

export interface ConsoleOrgProjectEnvContext {
  orgId: string;
  actorUserId: string;
  roles: readonly string[];
  projectId?: string;
  environmentId?: string;
}

export interface ConsoleOrgProjectEnvService {
  getOrganization(ctx: ConsoleOrgProjectEnvContext): Promise<ConsoleOrganization>;
  findDefaultOrganization(): Promise<ConsoleOrganization | null>;
  searchOrganizations(request: SearchConsoleOrganizationsRequest): Promise<ConsoleOrganization[]>;
  findOrganizationForScope(request: {
    projectId?: string;
    environmentId?: string;
  }): Promise<ConsoleOrganization | null>;
  upsertOrganization(
    ctx: ConsoleOrgProjectEnvContext,
    request: UpsertConsoleOrganizationRequest,
  ): Promise<ConsoleOrganization>;
  deleteOrganization(
    ctx: ConsoleOrgProjectEnvContext,
  ): Promise<{ deleted: boolean; organization: ConsoleOrganization | null }>;
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

function sortOrganizations(items: ConsoleOrganization[]): ConsoleOrganization[] {
  return [...items].sort((a, b) => {
    const nameDiff = a.name.localeCompare(b.name);
    if (nameDiff !== 0) return nameDiff;
    return a.id.localeCompare(b.id);
  });
}

function sortOrganizationsByCreatedAtDesc(items: ConsoleOrganization[]): ConsoleOrganization[] {
  return [...items].sort((a, b) => {
    const createdAtDiff = b.createdAt.localeCompare(a.createdAt);
    if (createdAtDiff !== 0) return createdAtDiff;
    return a.id.localeCompare(b.id);
  });
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

function cloneOrg(org: ConsoleOrganization): ConsoleOrganization {
  return { ...org };
}

function cloneProject(project: ConsoleProject): ConsoleProject {
  return { ...project };
}

function cloneEnvironment(environment: ConsoleEnvironment): ConsoleEnvironment {
  return { ...environment };
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

  function createOrgStore(ctx: ConsoleOrgProjectEnvContext): OrgStore {
    const currentNow = now();
    const createdAt = toIso(currentNow);
    const defaultName = humanizeId(ctx.orgId, 'Organization');
    const store: OrgStore = {
      org: {
        id: ctx.orgId,
        name: defaultName,
        slug: slugify(defaultName),
        status: 'ACTIVE',
        createdAt,
        updatedAt: createdAt,
      },
      projects: new Map<string, ConsoleProject>(),
      environments: new Map<string, ConsoleEnvironment>(),
    };
    stores.set(ctx.orgId, store);
    return store;
  }

  function getOrgStore(ctx: ConsoleOrgProjectEnvContext): OrgStore | undefined {
    return stores.get(ctx.orgId);
  }

  function ensureOrgStoreForWrite(ctx: ConsoleOrgProjectEnvContext): OrgStore {
    let store = stores.get(ctx.orgId);
    if (!store) return createOrgStore(ctx);
    return store;
  }

  return {
    async getOrganization(ctx): Promise<ConsoleOrganization> {
      const store = getOrgStore(ctx);
      if (!store) {
        throw new ConsoleOrgProjectEnvError(
          'organization_not_found',
          404,
          `Organization ${ctx.orgId} was not found`,
        );
      }
      return cloneOrg(store.org);
    },

    async findDefaultOrganization(): Promise<ConsoleOrganization | null> {
      const organizations = sortOrganizations(
        Array.from(stores.values()).map((store) => cloneOrg(store.org)),
      );
      if (organizations.length !== 1) return null;
      return cloneOrg(organizations[0]!);
    },

    async searchOrganizations(request): Promise<ConsoleOrganization[]> {
      const query = normalizeOrganizationSearchValue(request.query);
      const rawLimit = Number(request.limit || 0);
      const limit =
        Number.isFinite(rawLimit) && rawLimit > 0 ? Math.max(1, Math.floor(rawLimit)) : 10;
      if (!query) {
        return sortOrganizationsByCreatedAtDesc(
          Array.from(stores.values()).map((store) => cloneOrg(store.org)),
        )
          .slice(0, limit)
          .map((organization) => cloneOrg(organization));
      }
      const organizations: ConsoleOrganization[] = [];
      for (const store of stores.values()) {
        const organization = cloneOrg(store.org);
        const score = scoreOrganizationSearchResult(query, organization);
        if (!Number.isFinite(score)) continue;
        organizations.push(organization);
      }
      return sortOrganizationSearchResults(organizations, query)
        .slice(0, limit)
        .map((organization) => cloneOrg(organization));
    },

    async findOrganizationForScope(request): Promise<ConsoleOrganization | null> {
      const projectId = String(request.projectId || '').trim();
      const environmentId = String(request.environmentId || '').trim();

      if (environmentId) {
        for (const store of stores.values()) {
          const environment = store.environments.get(environmentId);
          if (!environment) continue;
          if (projectId && environment.projectId !== projectId) continue;
          return cloneOrg(store.org);
        }
      }

      if (projectId) {
        for (const store of stores.values()) {
          if (!store.projects.has(projectId)) continue;
          return cloneOrg(store.org);
        }
      }

      return null;
    },

    async upsertOrganization(
      ctx,
      request: UpsertConsoleOrganizationRequest,
    ): Promise<ConsoleOrganization> {
      const store = ensureOrgStoreForWrite(ctx);
      const currentNow = now();
      const defaultName = humanizeId(ctx.orgId, 'Organization');
      const nextName = String(request.name || '').trim() || store.org.name || defaultName;
      const nextSlug =
        String(request.slug || '').trim() || store.org.slug || slugify(nextName || defaultName);
      store.org.name = nextName;
      store.org.slug = slugify(nextSlug);
      store.org.updatedAt = toIso(currentNow);
      return cloneOrg(store.org);
    },

    async deleteOrganization(
      ctx,
    ): Promise<{ deleted: boolean; organization: ConsoleOrganization | null }> {
      const store = stores.get(ctx.orgId);
      if (!store) return { deleted: false, organization: null };
      const organization = cloneOrg(store.org);
      stores.delete(ctx.orgId);
      return { deleted: true, organization };
    },

    async listProjects(ctx, request?: ListConsoleProjectsRequest): Promise<ConsoleProject[]> {
      const store = getOrgStore(ctx);
      if (!store) return [];
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

    async createProject(ctx, request: CreateConsoleProjectRequest): Promise<ConsoleProject> {
      const store = getOrgStore(ctx);
      if (!store) {
        throw new ConsoleOrgProjectEnvError(
          'organization_not_found',
          404,
          `Organization ${ctx.orgId} was not found`,
        );
      }
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
      const liveEnvironmentsEnabled = request.liveEnvironmentsEnabled === true;
      for (const key of ['dev', 'staging', 'prod'] as const) {
        const environmentId = defaultEnvironmentId(projectId, key);
        if (store.environments.has(environmentId)) {
          throw new ConsoleOrgProjectEnvError(
            'environment_already_exists',
            409,
            `Environment ${environmentId} already exists`,
          );
        }
        store.environments.set(environmentId, {
          id: environmentId,
          orgId: ctx.orgId,
          projectId,
          key,
          signingRootVersion: DEFAULT_CONSOLE_SIGNING_ROOT_VERSION,
          name: environmentNameFromKey(key),
          status: defaultEnvironmentStatus(key, liveEnvironmentsEnabled),
          createdAt: ts,
          updatedAt: ts,
        });
      }
      return cloneProject({
        ...project,
        environmentCount: countEnvironmentsForProject(store, project.id),
      });
    },

    async updateProject(
      ctx,
      projectId: string,
      request: UpdateConsoleProjectRequest,
    ): Promise<ConsoleProject | null> {
      const store = getOrgStore(ctx);
      if (!store) return null;
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

    async archiveProject(ctx, projectId: string): Promise<ConsoleProject | null> {
      const store = getOrgStore(ctx);
      if (!store) return null;
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
      const store = getOrgStore(ctx);
      if (!store) return [];
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
      const store = getOrgStore(ctx);
      if (!store) {
        throw new ConsoleOrgProjectEnvError(
          'project_not_found',
          404,
          `Project ${request.projectId} was not found`,
        );
      }
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
        signingRootVersion: normalizeSigningRootVersion(
          request.signingRootVersion,
          DEFAULT_CONSOLE_SIGNING_ROOT_VERSION,
        ),
        name: request.name || environmentNameFromKey(request.key),
        status: request.status || 'ACTIVE',
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
      const store = getOrgStore(ctx);
      if (!store) return null;
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
      if (request.signingRootVersion !== undefined) {
        current.signingRootVersion = normalizeSigningRootVersion(request.signingRootVersion);
      }
      current.updatedAt = toIso(now());
      return cloneEnvironment(current);
    },

    async archiveEnvironment(ctx, environmentId: string): Promise<ConsoleEnvironment | null> {
      const store = getOrgStore(ctx);
      if (!store) return null;
      const current = store.environments.get(environmentId);
      if (!current) return null;
      current.status = 'ARCHIVED';
      current.updatedAt = toIso(now());
      return cloneEnvironment(current);
    },
  };
}
