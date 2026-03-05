import { test, expect } from '@playwright/test';
import {
  createInMemoryConsoleOrgProjectEnvService,
  isConsoleOrgProjectEnvError,
  parseListConsoleEnvironmentsRequest,
  parseListConsoleProjectsRequest,
} from '@server/console/orgProjectEnv';

async function expectOrgProjectEnvError(
  fn: () => unknown | Promise<unknown>,
  expectedCode: string,
): Promise<void> {
  let caught: unknown;
  try {
    await fn();
  } catch (error: unknown) {
    caught = error;
  }
  expect(caught).toBeTruthy();
  expect(isConsoleOrgProjectEnvError(caught)).toBe(true);
  expect(String((caught as any)?.code || '')).toBe(expectedCode);
}

test.describe('console org/project/environment parser and service semantics', () => {
  test('request parsers normalize valid status filters and reject invalid values', async () => {
    expect(parseListConsoleProjectsRequest({ status: 'active' })).toEqual({
      status: 'ACTIVE',
    });
    expect(parseListConsoleProjectsRequest({})).toEqual({});
    await expectOrgProjectEnvError(
      async () => parseListConsoleProjectsRequest({ status: 'invalid' }),
      'invalid_query',
    );

    expect(
      parseListConsoleEnvironmentsRequest({
        projectId: '  proj_a  ',
        status: 'archived',
      }),
    ).toEqual({
      projectId: 'proj_a',
      status: 'ARCHIVED',
    });
    expect(parseListConsoleEnvironmentsRequest({ projectId: '  proj_a  ' })).toEqual({
      projectId: 'proj_a',
    });
    await expectOrgProjectEnvError(
      async () => parseListConsoleEnvironmentsRequest({ status: 'unknown' }),
      'invalid_query',
    );
  });

  test('in-memory service applies project/environment status filters', async () => {
    const service = createInMemoryConsoleOrgProjectEnvService();
    const ctx = {
      orgId: 'org-service-filters-1',
      actorUserId: 'user-service-filters-1',
      roles: ['admin'],
    };

    await expectOrgProjectEnvError(
      async () => service.createProject(ctx, { id: 'proj_missing_org', name: 'Missing Org Project' }),
      'organization_not_found',
    );

    await service.upsertOrganization(ctx, {
      name: 'Service Filters Org',
      slug: 'service-filters-org',
    });

    await service.createProject(ctx, { id: 'proj_active', name: 'Project Active' });
    await service.createProject(ctx, { id: 'proj_archived', name: 'Project Archived' });
    const activeEnvironmentId = `${ctx.orgId}:proj_active:dev`;
    const archivedEnvironmentUnderActiveProjectId = `${ctx.orgId}:proj_active:staging`;
    const environmentUnderArchivedProjectId = `${ctx.orgId}:proj_archived:dev`;

    await service.archiveEnvironment(ctx, archivedEnvironmentUnderActiveProjectId);
    await service.archiveProject(ctx, 'proj_archived');

    const activeProjects = await service.listProjects(ctx, { status: 'ACTIVE' });
    const activeProjectIds = new Set(activeProjects.map((entry) => entry.id));
    expect(activeProjectIds.has('proj_active')).toBe(true);
    expect(activeProjectIds.has('proj_archived')).toBe(false);
    expect(activeProjects.every((entry) => entry.status === 'ACTIVE')).toBe(true);

    const archivedProjects = await service.listProjects(ctx, { status: 'ARCHIVED' });
    expect(archivedProjects.some((entry) => entry.id === 'proj_archived')).toBe(true);
    expect(archivedProjects.every((entry) => entry.status === 'ARCHIVED')).toBe(true);

    const activeEnvUnderActiveProject = await service.listEnvironments(ctx, {
      projectId: 'proj_active',
      status: 'ACTIVE',
    });
    const activeEnvUnderActiveProjectIds = new Set(
      activeEnvUnderActiveProject.map((entry) => entry.id),
    );
    expect(activeEnvUnderActiveProjectIds.has(activeEnvironmentId)).toBe(true);
    expect(activeEnvUnderActiveProjectIds.has(archivedEnvironmentUnderActiveProjectId)).toBe(false);

    const archivedEnvUnderActiveProject = await service.listEnvironments(ctx, {
      projectId: 'proj_active',
      status: 'ARCHIVED',
    });
    const archivedEnvUnderActiveProjectIds = new Set(
      archivedEnvUnderActiveProject.map((entry) => entry.id),
    );
    expect(archivedEnvUnderActiveProjectIds.has(archivedEnvironmentUnderActiveProjectId)).toBe(true);
    expect(archivedEnvUnderActiveProjectIds.has(activeEnvironmentId)).toBe(false);

    const activeEnvUnderArchivedProject = await service.listEnvironments(ctx, {
      projectId: 'proj_archived',
      status: 'ACTIVE',
    });
    expect(activeEnvUnderArchivedProject.length).toBe(0);

    const archivedEnvUnderArchivedProject = await service.listEnvironments(ctx, {
      projectId: 'proj_archived',
      status: 'ARCHIVED',
    });
    expect(
      archivedEnvUnderArchivedProject.some(
        (entry) => entry.id === environmentUnderArchivedProjectId && entry.status === 'ARCHIVED',
      ),
    ).toBe(true);
  });
});
